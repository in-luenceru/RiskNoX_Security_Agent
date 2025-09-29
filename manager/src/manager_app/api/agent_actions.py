"""
Agent Action API endpoints - Mirror the agent UI endpoints to trigger actions on agents
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
import structlog
import uuid

from ..db.database import get_db_session
from ..db.crud import create_command, get_agent_by_id
from ..ws.connection_manager import connection_manager

router = APIRouter(tags=["agent-actions"])
logger = structlog.get_logger()


# Request Models (matching agent UI expectations)
class AntivirusScanRequest(BaseModel):
    """Antivirus scan request"""
    path: str = Field(..., description="Path to scan or special values like SYSTEM_SCAN")
    scan_type: str = Field(..., description="Type of scan: directory, system, quick_system")
    agent_id: Optional[str] = Field(None, description="Specific agent ID (if not provided, uses all online agents)")


class WebBlockingRequest(BaseModel):
    """Web blocking request"""
    url: str = Field(..., description="URL to block")
    agent_id: Optional[str] = Field(None, description="Specific agent ID (if not provided, uses all online agents)")


class WebUnblockingRequest(BaseModel):
    """Web unblocking request"""
    url: str = Field(..., description="URL to unblock")
    agent_id: Optional[str] = Field(None, description="Specific agent ID (if not provided, uses all online agents)")


class PatchInstallRequest(BaseModel):
    """Patch installation request"""
    patch_ids: List[str] = Field(..., description="List of patch IDs to install")
    agent_id: Optional[str] = Field(None, description="Specific agent ID (if not provided, uses all online agents)")


# Response Models
class ScanSession(BaseModel):
    """Scan session response"""
    success: bool
    session_id: str
    message: str
    agent_results: Dict[str, bool] = {}


class ActionResponse(BaseModel):
    """Generic action response"""
    success: bool
    message: str
    agent_results: Dict[str, bool] = {}
    command_id: Optional[str] = None


class ScanStatusResponse(BaseModel):
    """Scan status response"""
    success: bool
    session: Dict[str, Any]


class ScanProgressResponse(BaseModel):
    """Scan progress response"""
    success: bool
    progress: Dict[str, Any]


# Antivirus endpoints (matching agent UI)
@router.post("/api/antivirus/scan", response_model=ScanSession)
async def start_antivirus_scan(
    request: AntivirusScanRequest,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Start an antivirus scan on one or more agents
    
    This endpoint mirrors the agent's /api/antivirus/scan endpoint
    but forwards the command to connected agents.
    """
    try:
        # Generate session ID for tracking
        session_id = str(uuid.uuid4())
        
        # Prepare command payload (matching agent backend expectations)
        command_payload = {
            "type": "antivirus_scan",
            "data": {
                "path": request.path,
                "scan_type": request.scan_type,
                "session_id": session_id
            },
            "session_id": session_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Determine target agents
        if request.agent_id:
            # Specific agent
            agent = await get_agent_by_id(db, request.agent_id)
            if not agent:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Agent {request.agent_id} not found"
                )
            target_agents = [request.agent_id]
        else:
            # All online agents
            target_agents = list(connection_manager.agent_connections.keys())
            if not target_agents:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="No agents are currently connected"
                )
        
        # Send command to agents and store in database
        agent_results = {}
        for agent_id in target_agents:
            try:
                # Store command in database
                command = await create_command(
                    db=db,
                    agent_id=agent_id,
                    command_type="antivirus_scan",
                    command_data=command_payload["data"],
                    priority="medium"
                )
                
                # Send to agent via WebSocket
                success = await connection_manager.send_command(agent_id, command_payload)
                agent_results[agent_id] = success
                
                if success:
                    logger.info("Antivirus scan command sent", 
                              agent_id=agent_id, session_id=session_id)
                else:
                    logger.warning("Failed to send antivirus scan command", 
                                 agent_id=agent_id, session_id=session_id)
                    
            except Exception as e:
                logger.error("Error sending scan command to agent", 
                           agent_id=agent_id, error=str(e))
                agent_results[agent_id] = False
        
        # Check if any commands were sent successfully
        success_count = sum(1 for success in agent_results.values() if success)
        
        return ScanSession(
            success=success_count > 0,
            session_id=session_id,
            message=f"Scan initiated on {success_count}/{len(target_agents)} agents",
            agent_results=agent_results
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to start antivirus scan", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start antivirus scan"
        )


@router.get("/api/antivirus/status/{session_id}")
async def get_scan_status(
    session_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get scan status for a session across all agents
    
    This aggregates scan status from all agents that are running the scan.
    """
    try:
        # Query commands for this session
        from ..db.crud import get_commands_by_type
        commands = await get_commands_by_type(
            db=db,
            command_type="antivirus_scan",
            limit=100  # Reasonable limit
        )
        
        # Filter commands by session_id
        session_commands = [
            cmd for cmd in commands 
            if cmd.command_data and cmd.command_data.get("session_id") == session_id
        ]
        
        if not session_commands:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan session {session_id} not found"
            )
        
        # Aggregate status from all agents
        total_files_scanned = 0
        total_threats_found = 0
        agent_statuses = []
        overall_status = "completed"  # Default to completed
        
        for command in session_commands:
            agent_status = {
                "agent_id": command.agent_id,
                "status": command.status,
                "files_scanned": 0,
                "threats_found": 0,
                "progress": 0
            }
            
            # Extract scan results if available
            if command.result:
                result_data = command.result
                agent_status["files_scanned"] = result_data.get("files_scanned", 0)
                agent_status["threats_found"] = result_data.get("threats_found", 0)
                agent_status["progress"] = result_data.get("progress", 0)
                
                total_files_scanned += agent_status["files_scanned"]
                total_threats_found += agent_status["threats_found"]
            
            # Update overall status based on agent statuses
            if command.status in ["pending", "sent", "running"]:
                overall_status = "running"
            elif command.status == "failed" and overall_status == "completed":
                overall_status = "failed"
                
            agent_statuses.append(agent_status)
        
        # Build aggregated response
        session_data = {
            "session_id": session_id,
            "status": overall_status,
            "files_scanned": total_files_scanned,
            "threats_found": total_threats_found,
            "agents": agent_statuses,
            "agent_count": len(session_commands),
            "completed_at": datetime.utcnow().isoformat() if overall_status == "completed" else None
        }
        
        return ScanStatusResponse(
            success=True,
            session=session_data
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get scan status", session_id=session_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan status"
        )


@router.get("/api/antivirus/scan-progress/{session_id}")
async def get_scan_progress(
    session_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get detailed scan progress for a session
    
    Returns real-time progress information from all agents.
    """
    try:
        # Similar to get_scan_status but with more detailed progress info
        from ..db.crud import get_commands_by_type
        commands = await get_commands_by_type(
            db=db,
            command_type="antivirus_scan",
            limit=100
        )
        
        session_commands = [
            cmd for cmd in commands 
            if cmd.command_data and cmd.command_data.get("session_id") == session_id
        ]
        
        if not session_commands:
            return ScanProgressResponse(
                success=False,
                progress={"error": "Session not found"}
            )
        
        # Aggregate progress data
        total_files = 0
        total_scanned = 0
        total_threats = 0
        scan_logs = []
        current_files = []
        
        for command in session_commands:
            if command.result:
                result = command.result
                total_files += result.get("total_files", 0)
                total_scanned += result.get("files_scanned", 0)
                total_threats += result.get("threats_found", 0)
                
                if result.get("current_file"):
                    current_files.append(f"Agent {command.agent_id}: {result['current_file']}")
                    
                if result.get("scan_log"):
                    scan_logs.extend(result["scan_log"])
        
        # Calculate overall progress
        progress_percent = (total_scanned / total_files * 100) if total_files > 0 else 0
        
        progress_data = {
            "status": "scanning" if any(cmd.status == "running" for cmd in session_commands) else "completed",
            "progress_percent": progress_percent,
            "files_scanned": total_scanned,
            "total_files": total_files,
            "threats_found": total_threats,
            "current_file": current_files[0] if current_files else "",
            "scan_speed": 0,  # Would need real-time calculation
            "scan_log": scan_logs[-50:] if scan_logs else []  # Last 50 entries
        }
        
        return ScanProgressResponse(
            success=True,
            progress=progress_data
        )
        
    except Exception as e:
        logger.error("Failed to get scan progress", session_id=session_id, error=str(e))
        return ScanProgressResponse(
            success=False,
            progress={"error": str(e)}
        )


# Web Blocking endpoints (matching agent UI)
@router.get("/api/web-blocking/urls")
async def get_blocked_urls(
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get blocked URLs from all agents
    
    This aggregates blocked URL lists from all connected agents.
    """
    try:
        # Query recent web blocking commands to get current state
        from ..db.crud import get_commands_by_type
        commands = await get_commands_by_type(
            db=db,
            command_type="web_blocking",
            limit=1000
        )
        
        # Build URL list from commands
        blocked_urls = []
        url_map = {}  # Track unique URLs
        
        for command in commands:
            if command.command_data and command.status == "completed":
                url_data = command.command_data
                url = url_data.get("url")
                if url and url not in url_map:
                    url_map[url] = {
                        "url": url,
                        "blocked_at": command.created_at.isoformat(),
                        "agent_count": 1
                    }
                elif url:
                    url_map[url]["agent_count"] += 1
        
        blocked_urls = list(url_map.values())
        
        return {
            "urls": blocked_urls,
            "total": len(blocked_urls)
        }
        
    except Exception as e:
        logger.error("Failed to get blocked URLs", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve blocked URLs"
        )


@router.post("/api/web-blocking/block", response_model=ActionResponse)
async def block_url(
    request: WebBlockingRequest,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Block a URL on one or more agents
    
    This mirrors the agent's web blocking endpoint.
    """
    try:
        # Prepare command payload
        command_payload = {
            "type": "web_block",
            "data": {
                "url": request.url,
                "action": "block"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Determine target agents
        if request.agent_id:
            target_agents = [request.agent_id]
            # Verify agent exists
            agent = await get_agent_by_id(db, request.agent_id)
            if not agent:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Agent {request.agent_id} not found"
                )
        else:
            target_agents = list(connection_manager.agent_connections.keys())
            if not target_agents:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="No agents are currently connected"
                )
        
        # Send commands to agents
        agent_results = {}
        for agent_id in target_agents:
            try:
                # Store command in database
                command = await create_command(
                    db=db,
                    agent_id=agent_id,
                    command_type="web_blocking",
                    command_data=command_payload["data"],
                    priority="medium"
                )
                
                # Send to agent
                success = await connection_manager.send_command(agent_id, command_payload)
                agent_results[agent_id] = success
                
                logger.info("Web blocking command sent", 
                          agent_id=agent_id, url=request.url)
                          
            except Exception as e:
                logger.error("Error sending web block command", 
                           agent_id=agent_id, error=str(e))
                agent_results[agent_id] = False
        
        success_count = sum(1 for success in agent_results.values() if success)
        
        return ActionResponse(
            success=success_count > 0,
            message=f"URL blocking initiated on {success_count}/{len(target_agents)} agents",
            agent_results=agent_results
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to block URL", url=request.url, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to block URL"
        )


@router.post("/api/web-blocking/unblock", response_model=ActionResponse)
async def unblock_url(
    request: WebUnblockingRequest,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Unblock a URL on one or more agents
    """
    try:
        # Prepare command payload
        command_payload = {
            "type": "web_unblock",
            "data": {
                "url": request.url,
                "action": "unblock"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Determine target agents
        if request.agent_id:
            target_agents = [request.agent_id]
            # Verify agent exists
            agent = await get_agent_by_id(db, request.agent_id)
            if not agent:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Agent {request.agent_id} not found"
                )
        else:
            target_agents = list(connection_manager.agent_connections.keys())
            if not target_agents:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="No agents are currently connected"
                )
        
        # Send commands to agents
        agent_results = {}
        for agent_id in target_agents:
            try:
                # Store command in database
                command = await create_command(
                    db=db,
                    agent_id=agent_id,
                    command_type="web_unblocking",
                    command_data=command_payload["data"],
                    priority="medium"
                )
                
                # Send to agent
                success = await connection_manager.send_command(agent_id, command_payload)
                agent_results[agent_id] = success
                
                logger.info("Web unblocking command sent", 
                          agent_id=agent_id, url=request.url)
                          
            except Exception as e:
                logger.error("Error sending web unblock command", 
                           agent_id=agent_id, error=str(e))
                agent_results[agent_id] = False
        
        success_count = sum(1 for success in agent_results.values() if success)
        
        return ActionResponse(
            success=success_count > 0,
            message=f"URL unblocking initiated on {success_count}/{len(target_agents)} agents",
            agent_results=agent_results
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to unblock URL", url=request.url, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to unblock URL"
        )


# Patch Management endpoints
@router.get("/api/patch-management/info")
async def get_patch_info(
    agent_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get patch management information from agents
    """
    try:
        # For now, return placeholder data
        # In a full implementation, this would query agents for their patch status
        
        if agent_id:
            # Specific agent patch info
            agent = await get_agent_by_id(db, agent_id)
            if not agent:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Agent {agent_id} not found"
                )
                
            # Query latest patch commands for this agent
            from ..db.crud import get_commands_by_type
            commands = await get_commands_by_type(
                db=db,
                command_type="patch_management",
                agent_id=agent_id,
                limit=10
            )
            
            patch_info = {
                "agent_id": agent_id,
                "system_info": {
                    "OSName": "Windows 10",
                    "OSVersion": "10.0.19045",
                    "OSBuild": "19045",
                    "ComputerName": agent.hostname
                },
                "pending_count": 5,  # Placeholder
                "installed_patches": [],
                "pending_updates": [],
                "update_history": [],
                "last_check": datetime.utcnow().isoformat(),
                "success": True
            }
        else:
            # Aggregate patch info from all agents
            patch_info = {
                "total_agents": len(connection_manager.agent_connections),
                "agents_with_updates": 3,  # Placeholder
                "critical_updates": 12,  # Placeholder
                "success": True
            }
        
        return patch_info
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get patch info", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve patch information"
        )


@router.post("/api/patch-management/install", response_model=ActionResponse)
async def install_patches(
    request: PatchInstallRequest,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Install patches on one or more agents
    """
    try:
        # Prepare command payload
        command_payload = {
            "type": "patch_install",
            "data": {
                "patch_ids": request.patch_ids,
                "action": "install"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Determine target agents
        if request.agent_id:
            target_agents = [request.agent_id]
            # Verify agent exists
            agent = await get_agent_by_id(db, request.agent_id)
            if not agent:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Agent {request.agent_id} not found"
                )
        else:
            target_agents = list(connection_manager.agent_connections.keys())
            if not target_agents:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="No agents are currently connected"
                )
        
        # Send commands to agents
        agent_results = {}
        for agent_id in target_agents:
            try:
                # Store command in database
                command = await create_command(
                    db=db,
                    agent_id=agent_id,
                    command_type="patch_management",
                    command_data=command_payload["data"],
                    priority="high"  # Patches are usually high priority
                )
                
                # Send to agent
                success = await connection_manager.send_command(agent_id, command_payload)
                agent_results[agent_id] = success
                
                logger.info("Patch install command sent", 
                          agent_id=agent_id, patch_count=len(request.patch_ids))
                          
            except Exception as e:
                logger.error("Error sending patch install command", 
                           agent_id=agent_id, error=str(e))
                agent_results[agent_id] = False
        
        success_count = sum(1 for success in agent_results.values() if success)
        
        return ActionResponse(
            success=success_count > 0,
            message=f"Patch installation initiated on {success_count}/{len(target_agents)} agents",
            agent_results=agent_results
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to install patches", patches=request.patch_ids, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to install patches"
        )


# System status endpoint
@router.get("/api/system/status")
async def get_system_status(
    agent_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get system status from agents
    """
    try:
        if agent_id:
            # Request system status from specific agent
            command_payload = {
                "type": "system_status",
                "data": {},
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Check if agent is connected
            if agent_id not in connection_manager.agent_connections:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=f"Agent {agent_id} is not connected"
                )
            
            # For now, return placeholder data
            # In a real implementation, we would send a command and wait for response
            return {
                "system": {
                    "cpu_percent": 25.5,
                    "memory_percent": 65.2,
                    "disk_percent": 45.8,
                    "uptime": "2 days, 14 hours"
                },
                "success": True
            }
        else:
            # Aggregate system status from all agents
            connected_agents = len(connection_manager.agent_connections)
            return {
                "connected_agents": connected_agents,
                "total_agents": connected_agents,  # Placeholder
                "system": {
                    "avg_cpu_percent": 30.0,
                    "avg_memory_percent": 60.0,
                    "avg_disk_percent": 50.0
                },
                "success": True
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get system status", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve system status"
        )
