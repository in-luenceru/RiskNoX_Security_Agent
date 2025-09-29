"""
Scan management endpoints
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
import structlog
import uuid

from ..db.database import get_db_session
from ..db.crud import get_commands_by_type, create_command, get_agent_by_id

router = APIRouter(tags=["scans"])
logger = structlog.get_logger()


class ScanRequest(BaseModel):
    """Scan request model"""
    agent_ids: List[str] = Field(..., description="List of agent IDs to scan")
    scan_type: str = Field(..., description="Type of scan: quick, full, custom")
    path: Optional[str] = Field(None, description="Scan path for custom scans")
    options: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional scan options")
    schedule: Optional[str] = Field(None, description="Cron expression for scheduled scans")


class ScanResult(BaseModel):
    """Scan result model"""
    id: str
    agent_id: str
    scan_type: str = Field(..., description="Type of scan: quick, full, custom")
    path: Optional[str] = Field(None, description="Scan path for custom scans")
    status: str = Field(..., description="Scan status: pending, running, completed, failed")
    threats_found: int = Field(default=0, description="Number of threats found")
    files_scanned: int = Field(default=0, description="Number of files scanned")
    started_at: str = Field(..., description="Scan start timestamp")
    completed_at: Optional[str] = Field(None, description="Scan completion timestamp")
    progress: Optional[int] = Field(None, description="Scan progress percentage")
    result_details: Optional[Dict[str, Any]] = Field(None, description="Detailed scan results")
    
    class Config:
        from_attributes = True


class ScanResultsResponse(BaseModel):
    """Scan results list response"""
    items: List[ScanResult]
    total: int
    page: int
    per_page: int
    pages: int


@router.post("/scans/trigger")
async def trigger_scan(
    scan_request: ScanRequest,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Trigger antivirus scan on specified agents
    
    Sends scan commands to the specified agents and returns scan IDs
    for tracking progress and results.
    """
    try:
        from ..ws.connection_manager import connection_manager
        from ..security.signer import sign_message
        
        scan_commands = []
        failed_agents = []
        
        for agent_id in scan_request.agent_ids:
            try:
                # Check if agent exists and is connected
                agent = await get_agent_by_id(db, agent_id)
                if not agent:
                    failed_agents.append({"agent_id": agent_id, "error": "Agent not found"})
                    continue
                
                # Check if agent is online
                is_online = agent_id in connection_manager.agent_connections
                if not is_online:
                    failed_agents.append({"agent_id": agent_id, "error": "Agent offline"})
                    continue
                
                # Create scan command
                command_payload = {
                    "scan_type": scan_request.scan_type,
                    "targets": [scan_request.path] if scan_request.path else [],
                    "options": scan_request.options
                }
                
                # Create command in database
                expires_at = datetime.utcnow() + timedelta(hours=24)  # 24 hour expiry
                command = await create_command(
                    db=db,
                    agent_id=agent_id,
                    command_type="scan",
                    payload=command_payload,
                    signature="",  # Will be signed before sending
                    created_by="admin",  # TODO: Get from auth context
                    expires_at=expires_at,
                    priority=3  # High priority for scans
                )
                
                # Send command to agent via WebSocket
                command_message = {
                    "type": "command",
                    "command_id": command.command_id,
                    "command_type": "scan",
                    "payload": command_payload,
                    "expires_at": expires_at.isoformat()
                }
                
                success = await connection_manager.send_command(agent_id, command_message)
                if success:
                    scan_commands.append({
                        "scan_id": command.command_id,
                        "agent_id": agent_id,
                        "status": "pending"
                    })
                    # Update command status to sent
                    from ..db.crud import update_command_status
                    await update_command_status(db, command.command_id, "sent")
                else:
                    failed_agents.append({"agent_id": agent_id, "error": "Failed to send command"})
                    
            except Exception as e:
                logger.error("Failed to create scan command", agent_id=agent_id, error=str(e))
                failed_agents.append({"agent_id": agent_id, "error": str(e)})
        
        return {
            "success": len(scan_commands) > 0,
            "message": f"Scan triggered on {len(scan_commands)} agents",
            "scan_commands": scan_commands,
            "failed_agents": failed_agents,
            "total_agents": len(scan_request.agent_ids),
            "successful_agents": len(scan_commands)
        }
        
    except Exception as e:
        logger.error("Failed to trigger scan", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to trigger scan"
        )


@router.get("/scans", response_model=ScanResultsResponse)
async def get_scan_results(
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    status: Optional[str] = Query(None, description="Filter by scan status"),
    scan_type: Optional[str] = Query(None, description="Filter by scan type"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get scan results with filtering and pagination
    
    Returns a list of scan results from agent scan commands,
    with optional filtering by agent, status, or scan type.
    """
    try:
        # Get scan commands from the database
        commands = await get_commands_by_type(
            db=db,
            command_type="scan",
            agent_id=agent_id,
            status=status,
            limit=per_page,
            offset=(page - 1) * per_page
        )
        
        # Convert commands to scan results
        scan_results = []
        for command in commands:
            # Extract scan information from command payload and results
            payload = command.payload or {}
            result = command.result or {}
            
            scan_result = ScanResult(
                id=command.command_id,
                agent_id=command.agent_id,
                scan_type=payload.get("scan_type", "unknown"),
                path=payload.get("path"),
                status=_map_command_status_to_scan_status(command.status),
                threats_found=result.get("threats_found", 0),
                files_scanned=result.get("files_scanned", 0),
                started_at=command.created_at.isoformat(),
                completed_at=command.completed_at.isoformat() if command.completed_at else None,
                progress=result.get("progress"),
                result_details=result
            )
            scan_results.append(scan_result)
        
        # Calculate total pages (simplified - in production, use a proper count query)
        total = len(scan_results)
        pages = (total + per_page - 1) // per_page
        
        return ScanResultsResponse(
            items=scan_results,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
        
    except Exception as e:
        logger.error("Failed to get scan results", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan results"
        )


@router.get("/scans/{scan_id}")
async def get_scan_details(
    scan_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get detailed information about a specific scan
    
    Returns complete scan information including results,
    threats found, and execution logs.
    """
    try:
        from ..db.crud import get_command_by_id
        
        command = await get_command_by_id(db, scan_id)
        if not command or command.command_type != "scan":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan {scan_id} not found"
            )
        
        payload = command.payload or {}
        result = command.result or {}
        
        scan_details = {
            "id": command.command_id,
            "agent_id": command.agent_id,
            "scan_type": payload.get("scan_type", "unknown"),
            "path": payload.get("path"),
            "status": _map_command_status_to_scan_status(command.status),
            "threats_found": result.get("threats_found", 0),
            "files_scanned": result.get("files_scanned", 0),
            "started_at": command.created_at.isoformat(),
            "completed_at": command.completed_at.isoformat() if command.completed_at else None,
            "progress": result.get("progress"),
            "result_details": result,
            "command_info": {
                "priority": command.priority,
                "expires_at": command.expires_at.isoformat(),
                "error_message": command.error_message
            }
        }
        
        return scan_details
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get scan details", scan_id=scan_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan details"
        )


@router.get("/scans/{scan_id}/logs")
async def get_scan_logs(
    scan_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get real-time logs for a running scan
    
    Returns scan execution logs and progress information
    for monitoring active scans.
    """
    try:
        from ..db.crud import get_command_by_id
        
        command = await get_command_by_id(db, scan_id)
        if not command or command.command_type != "scan":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan {scan_id} not found"
            )
        
        # Get logs from command result
        result = command.result or {}
        logs = result.get("execution_logs", [])
        
        # Add real-time status information if scan is active
        from ..ws.connection_manager import connection_manager
        agent_id = command.agent.agent_id if command.agent else None
        is_agent_online = agent_id in connection_manager.agent_connections if agent_id else False
        
        if command.status in ["running", "sent", "acknowledged"] and is_agent_online:
            # Add live status logs
            current_time = datetime.now().strftime('%H:%M:%S')
            if not logs:
                logs = []
            
            logs.extend([
                f"[{current_time}] Scan in progress on {command.agent.hostname if command.agent else 'unknown'}...",
                f"[{current_time}] Files scanned: {result.get('files_scanned', 0)}",
                f"[{current_time}] Threats found: {result.get('threats_found', 0)}",
                f"[{current_time}] Progress: {result.get('progress', 0)}%"
            ])
        elif command.status == "completed":
            if not logs:
                logs = [
                    "Scan completed successfully",
                    f"Total files scanned: {result.get('files_scanned', 0)}",
                    f"Threats found: {result.get('threats_found', 0)}",
                    f"Scan duration: {result.get('duration', 'Unknown')}"
                ]
        elif command.status == "failed":
            if not logs:
                logs = [f"Scan failed: {command.error_message or 'Unknown error'}"]
        elif command.status == "pending":
            logs = ["Scan queued and waiting to start..."]
        
        return {
            "scan_id": scan_id,
            "logs": logs,
            "status": command.status,
            "agent_id": agent_id,
            "agent_online": is_agent_online,
            "progress": result.get("progress", 0),
            "files_scanned": result.get("files_scanned", 0),
            "threats_found": result.get("threats_found", 0),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get scan logs", scan_id=scan_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve scan logs"
        )


@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Cancel a running scan
    
    Sends cancel command to the agent and updates scan status.
    """
    try:
        from ..db.crud import get_command_by_id, update_command_status
        from ..ws.connection_manager import connection_manager
        
        command = await get_command_by_id(db, scan_id)
        if not command or command.command_type != "scan":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan {scan_id} not found"
            )
        
        if command.status not in ["pending", "sent", "acknowledged", "running"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel scan with status: {command.status}"
            )
        
        agent_id = command.agent.agent_id if command.agent else None
        if agent_id and agent_id in connection_manager.agent_connections:
            # Send cancel command to agent
            cancel_message = {
                "type": "cancel_command",
                "command_id": scan_id,
                "reason": "user_requested"
            }
            
            await connection_manager.send_command(agent_id, cancel_message)
        
        # Update command status
        await update_command_status(db, scan_id, "cancelled", error_message="Cancelled by user")
        
        return {
            "success": True,
            "message": f"Scan {scan_id} cancelled successfully",
            "scan_id": scan_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to cancel scan", scan_id=scan_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel scan"
        )


def _map_command_status_to_scan_status(command_status: str) -> str:
    """Map command status to scan status"""
    status_mapping = {
        "pending": "pending",
        "sent": "pending", 
        "acknowledged": "running",
        "running": "running",
        "completed": "completed",
        "failed": "failed",
        "expired": "failed"
    }
    return status_mapping.get(command_status, "unknown")