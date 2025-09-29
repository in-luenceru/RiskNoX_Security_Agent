"""
Admin Action API endpoints for Manager Bridge
Provides REST endpoints that accept admin UI actions and translate them to agent commands
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import uuid
from datetime import datetime
import logging

from ...bridge import create_manager_bridge, AdminActionHelpers
from ..dependencies import get_database, get_connection_manager, get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin-actions"])
security = HTTPBearer()


# Request/Response Models

class AdminActionRequest(BaseModel):
    """Request model for admin action trigger"""
    agent_id: str = Field(..., description="Target agent UUID")
    action: str = Field(..., description="Action type (run_scan, block_url, etc.)")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Action-specific payload")
    priority: int = Field(default=5, ge=1, le=10, description="Command priority (1=highest, 10=lowest)")


class BulkAdminActionRequest(BaseModel):
    """Request model for bulk admin actions"""
    agent_ids: List[str] = Field(..., description="Target agent UUIDs")
    action: str = Field(..., description="Action type")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Action-specific payload")
    priority: int = Field(default=5, ge=1, le=10, description="Command priority")


class AdminActionResponse(BaseModel):
    """Response model for admin action"""
    success: bool
    command_id: Optional[str] = None
    status: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None
    error_type: Optional[str] = None


class BulkAdminActionResponse(BaseModel):
    """Response model for bulk admin actions"""
    success: bool
    total_agents: int
    successful: int
    failed: int
    results: List[Dict[str, Any]]


class CommandStatusResponse(BaseModel):
    """Response model for command status"""
    command_id: str
    status: str
    created_at: datetime
    sent_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


class AgentStatsResponse(BaseModel):
    """Response model for agent command statistics"""
    agent_id: str
    pending: int
    sent: int
    queued: int
    failed: int


# Dependency to get manager bridge instance
async def get_manager_bridge():
    """Get configured manager bridge instance"""
    # This would be injected by the FastAPI app
    # For now, create a new instance (in production, use dependency injection)
    connection_manager = get_connection_manager()
    database = get_database()
    
    return await create_manager_bridge(
        connection_manager=connection_manager,
        database=database,
        private_key_path="certs/manager_private_key.pem"  # Configure path
    )


# API Endpoints

@router.post("/action/trigger", response_model=AdminActionResponse)
async def trigger_admin_action(
    request: AdminActionRequest,
    bridge = Depends(get_manager_bridge),
    current_user = Depends(get_current_user)
):
    """
    Trigger an admin action on a specific agent
    
    This endpoint accepts admin UI actions and translates them to agent commands
    using the exact same payload format as the local UI would send.
    
    Supported actions:
    - run_scan: Start antivirus scan
    - cancel_scan: Cancel running scan
    - block_url: Block URL via hosts file
    - unblock_url: Unblock URL
    - get_blocked_urls: List blocked URLs
    - install_patches: Install Windows updates
    - check_patches: Check for available updates
    - get_patch_info: Get patch management info
    - get_system_info: Get system status
    - restart_agent: Restart agent
    - update_config: Update agent configuration
    - cleanup_agent: Clean agent temp files
    """
    try:
        logger.info("Admin action triggered",
                   action=request.action,
                   agent_id=request.agent_id,
                   user=current_user.get("username", "unknown"))
        
        # Execute admin action through bridge
        result = await bridge.execute_admin_action(
            agent_id=request.agent_id,
            action=request.action,
            payload=request.payload,
            issued_by=current_user.get("username", "admin"),
            priority=request.priority
        )
        
        return AdminActionResponse(**result)
        
    except Exception as e:
        logger.error("Admin action failed",
                    action=request.action,
                    agent_id=request.agent_id,
                    error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/action/bulk", response_model=BulkAdminActionResponse)
async def trigger_bulk_admin_action(
    request: BulkAdminActionRequest,
    bridge = Depends(get_manager_bridge),
    current_user = Depends(get_current_user)
):
    """
    Trigger an admin action on multiple agents
    
    Executes the same action on multiple agents in parallel.
    Useful for bulk operations like scanning all agents or blocking URLs across the fleet.
    """
    try:
        logger.info("Bulk admin action triggered",
                   action=request.action,
                   agent_count=len(request.agent_ids),
                   user=current_user.get("username", "unknown"))
        
        # Execute bulk admin action through bridge
        result = await bridge.execute_bulk_action(
            agent_ids=request.agent_ids,
            action=request.action,
            payload=request.payload,
            issued_by=current_user.get("username", "admin"),
            priority=request.priority
        )
        
        return BulkAdminActionResponse(**result)
        
    except Exception as e:
        logger.error("Bulk admin action failed",
                    action=request.action,
                    agent_count=len(request.agent_ids),
                    error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/command/{command_id}/status", response_model=CommandStatusResponse)
async def get_command_status(
    command_id: str,
    bridge = Depends(get_manager_bridge),
    current_user = Depends(get_current_user)
):
    """Get status of a specific command"""
    try:
        command_info = await bridge.get_command_status(command_id)
        
        if not command_info:
            raise HTTPException(status_code=404, detail="Command not found")
        
        return CommandStatusResponse(
            command_id=command_id,
            status=command_info["status"],
            created_at=command_info["created_at"],
            sent_at=command_info.get("sent_at"),
            completed_at=command_info.get("completed_at"),
            result=command_info.get("result"),
            error_message=command_info.get("error_message")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get command status", command_id=command_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agent/{agent_id}/stats", response_model=AgentStatsResponse)
async def get_agent_command_stats(
    agent_id: str,
    bridge = Depends(get_manager_bridge),
    current_user = Depends(get_current_user)
):
    """Get command statistics for an agent"""
    try:
        stats = await bridge.get_agent_command_stats(agent_id)
        
        return AgentStatsResponse(
            agent_id=agent_id,
            **stats
        )
        
    except Exception as e:
        logger.error("Failed to get agent stats", agent_id=agent_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/actions", response_model=List[str])
async def get_supported_actions(
    bridge = Depends(get_manager_bridge),
    current_user = Depends(get_current_user)
):
    """Get list of supported admin actions"""
    return bridge.get_supported_actions()


# Helper endpoints for common actions

@router.post("/scan/quick")
async def trigger_quick_scan(
    agent_ids: List[str],
    bridge = Depends(get_manager_bridge),
    current_user = Depends(get_current_user)
):
    """Helper endpoint to trigger quick scan on multiple agents"""
    payload = AdminActionHelpers.create_scan_action(scan_type="quick")
    
    request = BulkAdminActionRequest(
        agent_ids=agent_ids,
        action="run_scan",
        payload=payload,
        priority=3  # High priority for security scans
    )
    
    return await trigger_bulk_admin_action(request, bridge, current_user)


@router.post("/scan/full")
async def trigger_full_scan(
    agent_ids: List[str],
    bridge = Depends(get_manager_bridge),
    current_user = Depends(get_current_user)
):
    """Helper endpoint to trigger full system scan on multiple agents"""
    payload = AdminActionHelpers.create_scan_action(scan_type="full")
    
    request = BulkAdminActionRequest(
        agent_ids=agent_ids,
        action="run_scan",
        payload=payload,
        priority=4  # Medium priority for full scans
    )
    
    return await trigger_bulk_admin_action(request, bridge, current_user)


@router.post("/web/block")
async def block_urls(
    agent_ids: List[str],
    urls: List[str],
    category: str = "admin_blocked",
    bridge = Depends(get_manager_bridge),
    current_user = Depends(get_current_user)
):
    """Helper endpoint to block URLs on multiple agents"""
    payload = AdminActionHelpers.create_web_block_action(urls, category)
    
    request = BulkAdminActionRequest(
        agent_ids=agent_ids,
        action="block_url",
        payload=payload,
        priority=2  # High priority for security blocking
    )
    
    return await trigger_bulk_admin_action(request, bridge, current_user)


@router.post("/web/unblock")
async def unblock_urls(
    agent_ids: List[str],
    urls: List[str],
    bridge = Depends(get_manager_bridge),
    current_user = Depends(get_current_user)
):
    """Helper endpoint to unblock URLs on multiple agents"""
    payload = {"urls": urls}
    
    request = BulkAdminActionRequest(
        agent_ids=agent_ids,
        action="unblock_url",
        payload=payload,
        priority=5  # Normal priority for unblocking
    )
    
    return await trigger_bulk_admin_action(request, bridge, current_user)


@router.post("/patch/install")
async def install_patches(
    agent_ids: List[str],
    patch_ids: Optional[List[str]] = None,
    auto_reboot: bool = False,
    bridge = Depends(get_manager_bridge),
    current_user = Depends(get_current_user)
):
    """Helper endpoint to install patches on multiple agents"""
    payload = AdminActionHelpers.create_patch_install_action(patch_ids, auto_reboot)
    
    request = BulkAdminActionRequest(
        agent_ids=agent_ids,
        action="install_patches",
        payload=payload,
        priority=3  # High priority for security patches
    )
    
    return await trigger_bulk_admin_action(request, bridge, current_user)


@router.post("/system/info")
async def get_system_info(
    agent_ids: List[str],
    include_network: bool = True,
    include_processes: bool = False,
    bridge = Depends(get_manager_bridge),
    current_user = Depends(get_current_user)
):
    """Helper endpoint to get system info from multiple agents"""
    payload = AdminActionHelpers.create_system_info_action(include_network, include_processes)
    
    request = BulkAdminActionRequest(
        agent_ids=agent_ids,
        action="get_system_info",
        payload=payload,
        priority=6  # Lower priority for info gathering
    )
    
    return await trigger_bulk_admin_action(request, bridge, current_user)


# Background task for periodic cleanup
@router.post("/maintenance/cleanup")
async def trigger_maintenance_cleanup(
    background_tasks: BackgroundTasks,
    bridge = Depends(get_manager_bridge),
    current_user = Depends(get_current_user)
):
    """Trigger periodic maintenance cleanup"""
    async def cleanup_task():
        await bridge.cleanup_expired_commands()
        await bridge.retry_failed_commands()
    
    background_tasks.add_task(cleanup_task)
    
    return {"message": "Maintenance cleanup scheduled"}


# Include router in main app
def include_admin_router(app):
    """Include admin action router in FastAPI app"""
    app.include_router(router)