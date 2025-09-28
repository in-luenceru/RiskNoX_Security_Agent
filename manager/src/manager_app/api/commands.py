"""
Command management endpoints
"""

import uuid
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
import structlog

from ..db.database import get_db_session
from ..db.crud import create_command, get_command_by_id, get_pending_commands_for_agent
from ..security.signer import sign_command_payload

router = APIRouter(tags=["commands"])
logger = structlog.get_logger()


class CommandRequest(BaseModel):
    """Command creation request"""
    agent_id: str = Field(..., description="Target agent ID")
    command_type: str = Field(..., description="Command type")
    payload: Dict[str, Any] = Field(..., description="Command payload")
    priority: int = Field(default=5, ge=1, le=10, description="Command priority (1=highest)")
    ttl_minutes: int = Field(default=60, ge=1, le=1440, description="Command TTL in minutes")


class CommandResponse(BaseModel):
    """Command response model"""
    command_id: str
    agent_id: str
    command_type: str
    status: str
    priority: int
    created_at: str
    expires_at: str
    sent_at: Optional[str]
    ack_at: Optional[str]
    completed_at: Optional[str]
    result: Optional[Dict[str, Any]]
    error_message: Optional[str]
    
    class Config:
        from_attributes = True


class ScanCommandRequest(BaseModel):
    """Scan command request"""
    agent_ids: List[str] = Field(..., description="Target agent IDs")
    scan_type: str = Field(..., description="Scan type: full, quick, custom")
    targets: List[str] = Field(default=[], description="Scan targets for custom scan")
    priority: int = Field(default=3, ge=1, le=10)
    
class WebBlockCommandRequest(BaseModel):
    """Web blocking command request"""
    agent_ids: List[str] = Field(..., description="Target agent IDs")
    action: str = Field(..., description="Action: block or unblock")
    urls: List[str] = Field(..., description="URLs to block/unblock")
    priority: int = Field(default=5, ge=1, le=10)

class PatchCommandRequest(BaseModel):
    """Patch installation command request"""
    agent_ids: List[str] = Field(..., description="Target agent IDs")
    action: str = Field(..., description="Action: install, check, rollback")
    patch_ids: List[str] = Field(default=[], description="Specific patch IDs")
    options: Dict[str, Any] = Field(default={}, description="Installation options")
    priority: int = Field(default=2, ge=1, le=10)


@router.post("/commands", response_model=CommandResponse)
async def create_agent_command(
    command_request: CommandRequest,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Create a new command for an agent
    
    The command will be digitally signed and queued for delivery.
    Agents will receive commands via WebSocket or polling.
    
    Supported command types:
    - scan: Antivirus scanning
    - patch: Patch installation  
    - config: Configuration updates
    - web_block/web_unblock: Web blocking management
    - system_info: System information collection
    """
    try:
        # Calculate expiration
        expires_at = datetime.utcnow() + timedelta(minutes=command_request.ttl_minutes)
        
        # Create command payload with metadata
        command_payload = {
            "command_id": str(uuid.uuid4()),
            "command_type": command_request.command_type,
            "payload": command_request.payload,
            "issued_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at.isoformat(),
            "issued_by": "admin",  # TODO: Get from auth context
        }
        
        # Sign the command payload
        signature = sign_command_payload(command_payload)
        if not signature:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to sign command"
            )
        
        # Create command in database
        command = await create_command(
            db=db,
            agent_id=command_request.agent_id,
            command_type=command_request.command_type,
            payload=command_payload,
            signature=signature,
            created_by="admin",  # TODO: Get from auth context
            expires_at=expires_at,
            priority=command_request.priority
        )
        
        logger.info(
            "Command created",
            command_id=command.command_id,
            agent_id=command_request.agent_id,
            command_type=command_request.command_type
        )
        
        return CommandResponse(
            command_id=command.command_id,
            agent_id=command_request.agent_id,
            command_type=command.command_type,
            status=command.status,
            priority=command.priority,
            created_at=command.created_at.isoformat(),
            expires_at=command.expires_at.isoformat(),
            sent_at=command.sent_at.isoformat() if command.sent_at else None,
            ack_at=command.ack_at.isoformat() if command.ack_at else None,
            completed_at=command.completed_at.isoformat() if command.completed_at else None,
            result=command.result,
            error_message=command.error_message
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to create command", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create command"
        )


@router.get("/commands/{command_id}", response_model=CommandResponse)  
async def get_command_status(
    command_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get command status and results
    
    Returns current command status, execution results,
    and any error messages.
    """
    try:
        command = await get_command_by_id(db, command_id)
        if not command:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Command {command_id} not found"
            )
        
        return CommandResponse(
            command_id=command.command_id,
            agent_id=command.agent.agent_id,
            command_type=command.command_type,
            status=command.status,
            priority=command.priority,
            created_at=command.created_at.isoformat(),
            expires_at=command.expires_at.isoformat(),
            sent_at=command.sent_at.isoformat() if command.sent_at else None,
            ack_at=command.ack_at.isoformat() if command.ack_at else None,
            completed_at=command.completed_at.isoformat() if command.completed_at else None,
            result=command.result,
            error_message=command.error_message
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get command status", command_id=command_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve command status"
        )


@router.get("/agents/{agent_id}/commands")
async def get_agent_commands(
    agent_id: str,
    since: Optional[str] = Query(None, description="Return commands since this timestamp"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get pending commands for an agent (polling endpoint)
    
    This endpoint is used by agents for fallback polling
    when WebSocket connection is not available.
    """
    try:
        commands = await get_pending_commands_for_agent(db, agent_id)
        
        # Filter by timestamp if provided
        if since:
            try:
                since_dt = datetime.fromisoformat(since.replace('Z', '+00:00'))
                commands = [cmd for cmd in commands if cmd.created_at > since_dt]
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid timestamp format"
                )
        
        # Convert to response format
        command_responses = []
        for command in commands:
            # Include signed payload for agent verification
            command_data = {
                "command_id": command.command_id,
                "command_type": command.command_type,
                "payload": command.payload,
                "signature": command.signature,
                "priority": command.priority,
                "expires_at": command.expires_at.isoformat()
            }
            command_responses.append(command_data)
        
        logger.info(
            "Agent commands retrieved",
            agent_id=agent_id,
            command_count=len(command_responses)
        )
        
        return {
            "agent_id": agent_id,
            "commands": command_responses,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get agent commands", agent_id=agent_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve agent commands"
        )


class CommandResult(BaseModel):
    """Command result submission"""
    command_id: str = Field(..., description="Command ID")
    status: str = Field(..., description="Command status: ack, completed, failed")
    result: Optional[Dict[str, Any]] = Field(None, description="Command execution result")
    error_message: Optional[str] = Field(None, description="Error message if failed")


@router.post("/agents/{agent_id}/results")
async def submit_command_result(
    agent_id: str,
    command_result: CommandResult,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Submit command execution results (agent endpoint)
    
    Agents use this endpoint to report command acknowledgment,
    completion status, and execution results.
    """
    try:
        from ..db.crud import update_command_status
        
        command = await update_command_status(
            db=db,
            command_id=command_result.command_id,
            status=command_result.status,
            result=command_result.result,
            error_message=command_result.error_message
        )
        
        if not command:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Command {command_result.command_id} not found"
            )
        
        logger.info(
            "Command result submitted",
            agent_id=agent_id,
            command_id=command_result.command_id,
            status=command_result.status
        )
        
        return {
            "success": True,
            "message": "Command result received",
            "command_id": command_result.command_id,
            "status": command_result.status
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to submit command result",
            agent_id=agent_id,
            command_id=command_result.command_id,
            error=str(e)
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit command result"
        )


@router.post("/commands/scan")
async def trigger_scan_command(
    scan_request: ScanCommandRequest,
    db: AsyncSession = Depends(get_db_session)
):
    """Trigger antivirus scan on multiple agents"""
    from ..tasks.command_delivery import broadcast_command_to_agents
    
    # Prepare scan command
    scan_command = {
        "command_type": "scan",
        "payload": {
            "scan_type": scan_request.scan_type,
            "targets": scan_request.targets,
            "options": {
                "recursive": True,
                "follow_symlinks": False,
                "max_scan_size": "100MB"
            }
        },
        "priority": scan_request.priority,
        "ttl_minutes": 240  # 4 hour TTL for scans
    }
    
    # Broadcast to agents using Celery task
    task_result = broadcast_command_to_agents.apply_async(
        args=[scan_command, scan_request.agent_ids]
    )
    
    logger.info("Scan command broadcast", 
               agent_count=len(scan_request.agent_ids),
               scan_type=scan_request.scan_type,
               task_id=task_result.id)
    
    return {
        "success": True,
        "message": f"Scan command sent to {len(scan_request.agent_ids)} agents",
        "task_id": task_result.id,
        "scan_type": scan_request.scan_type,
        "agent_count": len(scan_request.agent_ids)
    }


@router.post("/commands/web-block")
async def trigger_web_block_command(
    block_request: WebBlockCommandRequest,
    db: AsyncSession = Depends(get_db_session)
):
    """Trigger web blocking/unblocking on multiple agents"""
    from ..tasks.command_delivery import broadcast_command_to_agents
    
    command_type = "web_block" if block_request.action == "block" else "web_unblock"
    
    # Prepare web blocking command
    web_command = {
        "command_type": command_type,
        "payload": {
            "urls": block_request.urls,
            "action": block_request.action
        },
        "priority": block_request.priority,
        "ttl_minutes": 60
    }
    
    # Broadcast to agents
    task_result = broadcast_command_to_agents.apply_async(
        args=[web_command, block_request.agent_ids]
    )
    
    logger.info("Web block command broadcast",
               agent_count=len(block_request.agent_ids),
               action=block_request.action,
               url_count=len(block_request.urls),
               task_id=task_result.id)
    
    return {
        "success": True,
        "message": f"Web {block_request.action} command sent to {len(block_request.agent_ids)} agents",
        "task_id": task_result.id,
        "action": block_request.action,
        "urls": block_request.urls,
        "agent_count": len(block_request.agent_ids)
    }


@router.post("/commands/patch")
async def trigger_patch_command(
    patch_request: PatchCommandRequest,
    db: AsyncSession = Depends(get_db_session)
):
    """Trigger patch management on multiple agents"""
    from ..tasks.command_delivery import broadcast_command_to_agents
    
    # Prepare patch command
    patch_command = {
        "command_type": "patch",
        "payload": {
            "action": patch_request.action,
            "patch_ids": patch_request.patch_ids,
            "options": {
                "auto_reboot": patch_request.options.get("auto_reboot", False),
                "backup_before_install": patch_request.options.get("backup_before_install", True),
                "rollback_on_failure": patch_request.options.get("rollback_on_failure", True),
                **patch_request.options
            }
        },
        "priority": patch_request.priority,
        "ttl_minutes": 480  # 8 hour TTL for patches
    }
    
    # Broadcast to agents
    task_result = broadcast_command_to_agents.apply_async(
        args=[patch_command, patch_request.agent_ids]
    )
    
    logger.info("Patch command broadcast",
               agent_count=len(patch_request.agent_ids),
               action=patch_request.action,
               patch_count=len(patch_request.patch_ids),
               task_id=task_result.id)
    
    return {
        "success": True,
        "message": f"Patch {patch_request.action} command sent to {len(patch_request.agent_ids)} agents",
        "task_id": task_result.id,
        "action": patch_request.action,
        "agent_count": len(patch_request.agent_ids)
    }


@router.post("/commands/system-info")
async def trigger_system_info_command(
    agent_ids: List[str],
    db: AsyncSession = Depends(get_db_session)
):
    """Collect system information from multiple agents"""
    from ..tasks.command_delivery import broadcast_command_to_agents
    
    # Prepare system info command  
    info_command = {
        "command_type": "system_info",
        "payload": {
            "collect_hardware": True,
            "collect_software": True,
            "collect_network": True,
            "collect_security": True
        },
        "priority": 4,
        "ttl_minutes": 30
    }
    
    # Broadcast to agents
    task_result = broadcast_command_to_agents.apply_async(
        args=[info_command, agent_ids]
    )
    
    logger.info("System info command broadcast",
               agent_count=len(agent_ids),
               task_id=task_result.id)
    
    return {
        "success": True,
        "message": f"System info collection started for {len(agent_ids)} agents",
        "task_id": task_result.id,
        "agent_count": len(agent_ids)
    }