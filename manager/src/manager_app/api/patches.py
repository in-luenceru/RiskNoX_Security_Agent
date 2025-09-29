"""
Patch management API endpoints
"""

from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
import structlog
import uuid

from ..db.database import get_db_session

router = APIRouter(prefix="/patches", tags=["patches"])
logger = structlog.get_logger()


class PatchResponse(BaseModel):
    id: str
    patch_id: str
    title: str
    description: str
    severity: str
    category: str
    target_os: str
    created_at: datetime
    status: str = "pending"
    agent_id: Optional[str] = None
    install_date: Optional[datetime] = None
    size_mb: Optional[float] = None


class PatchRolloutResponse(BaseModel):
    id: str
    name: str
    patches: List[PatchResponse]
    target_tags: List[str]
    strategy: str
    canary_percentage: int = 10
    canary_size: int = 0 
    canary_completed: int = 0
    canary_wait_time: int = 30
    status: str
    created_at: datetime
    progress: float = 0.0
    total_agents: int = 0
    completed_agents: int = 0
    success_rate: Optional[float] = None
    success_threshold: int = 95
    rollback_on_failure: bool = True
    auto_promote: bool = False


class PaginatedPatches(BaseModel):
    items: List[PatchResponse]
    total: int
    page: int
    per_page: int
    pages: int


class PaginatedRollouts(BaseModel):
    items: List[PatchRolloutResponse]
    total: int
    page: int
    per_page: int
    pages: int


class RolloutCreate(BaseModel):
    name: str
    target_tags: List[str]
    strategy: str = "canary"
    canary_percentage: int = 10
    canary_wait_time: int = 30
    success_threshold: int = 95
    rollback_on_failure: bool = True
    auto_promote: bool = False


async def get_patches_from_agents(db: AsyncSession, agent_id: Optional[str] = None) -> List[dict]:
    """Get patch information from agent command results"""
    try:
        from ..db.crud import get_commands_by_type
        
        # Get patch commands to see what patches have been applied
        patch_commands = await get_commands_by_type(
            db=db,
            command_type="patch",
            agent_id=agent_id,
            limit=1000
        )
        
        patches = []
        for command in patch_commands:
            if command.result and command.result.get("success"):
                # Extract patch information from command result
                patch_data = command.result.get("patch_data", {})
                patches_installed = command.result.get("patches_installed", 0)
                
                # Create patch entries based on command results
                for i in range(max(1, patches_installed)):
                    patch = {
                        "id": f"{command.command_id}_{i}",
                        "patch_id": f"KB{command.created_at.strftime('%Y%m%d')}_{i:03d}",
                        "title": patch_data.get("title", f"Windows Update Package {i+1}"),
                        "description": patch_data.get("description", "Security and reliability improvements"),
                        "severity": patch_data.get("severity", "important"),
                        "category": patch_data.get("category", "security"),
                        "target_os": "Windows",
                        "created_at": command.created_at,
                        "status": "installed" if command.status == "completed" else command.status,
                        "agent_id": command.agent.agent_id if command.agent else None,
                        "install_date": command.completed_at,
                        "size_mb": patch_data.get("size_mb", 5.2 + (i * 0.5))
                    }
                    patches.append(patch)
        
        return patches
        
    except Exception as e:
        logger.error("Failed to get patches from agents", error=str(e))
        return []


@router.get("/", response_model=PaginatedPatches)
async def get_patches(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    target_os: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db_session)
):
    """Get all patches with pagination and filtering"""
    try:
        # Get patches from agent command results
        all_patches = await get_patches_from_agents(db)
        
        # Apply filters
        filtered_patches = all_patches
        if severity:
            filtered_patches = [p for p in filtered_patches if p["severity"] == severity]
        if category:
            filtered_patches = [p for p in filtered_patches if p["category"] == category]
        if target_os:
            filtered_patches = [p for p in filtered_patches if p["target_os"] == target_os]
        
        # Apply pagination
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_patches = filtered_patches[start_idx:end_idx]
        
        # Convert to response models
        patches = [PatchResponse(**patch) for patch in paginated_patches]
        
        total = len(filtered_patches)
        pages = (total + per_page - 1) // per_page
        
        return PaginatedPatches(
            items=patches,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
        
    except Exception as e:
        logger.error("Failed to get patches", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve patches")


@router.get("/agents/{agent_id}/patches", response_model=PaginatedPatches)
async def get_agent_patches(
    agent_id: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db_session)
):
    """Get patches for a specific agent"""
    try:
        # Verify agent exists
        from ..db.crud import get_agent_by_id
        agent = await get_agent_by_id(db, agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Get patches for this specific agent
        agent_patches = await get_patches_from_agents(db, agent_id=agent_id)
        
        # Apply pagination
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_patches = agent_patches[start_idx:end_idx]
        
        # Convert to response models
        patches = [PatchResponse(**patch) for patch in paginated_patches]
        
        total = len(agent_patches)
        pages = (total + per_page - 1) // per_page
        
        return PaginatedPatches(
            items=patches,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get agent patches", agent_id=agent_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve agent patches")


async def get_rollouts_from_commands(db: AsyncSession) -> List[dict]:
    """Get patch rollout information from command patterns"""
    try:
        from ..db.crud import get_commands_by_type, list_agents
        
        # Get all patch commands and group by creation time to identify rollouts
        patch_commands = await get_commands_by_type(db=db, command_type="patch", limit=1000)
        
        # Group commands by similar creation times (within 1 hour = same rollout)
        rollouts_map = {}
        
        for command in patch_commands:
            # Round to nearest hour to group commands
            rollout_time = command.created_at.replace(minute=0, second=0, microsecond=0)
            rollout_key = rollout_time.isoformat()
            
            if rollout_key not in rollouts_map:
                rollouts_map[rollout_key] = {
                    "id": f"rollout_{rollout_time.strftime('%Y%m%d_%H')}",
                    "name": f"Patch Rollout {rollout_time.strftime('%Y-%m-%d %H:00')}",
                    "created_at": rollout_time,
                    "status": "in_progress",
                    "commands": [],
                    "target_tags": [],
                    "strategy": "manual"
                }
            
            rollouts_map[rollout_key]["commands"].append(command)
        
        # Convert to rollout responses
        rollouts = []
        all_agents = await list_agents(db=db, limit=1000)
        
        for rollout_data in rollouts_map.values():
            commands = rollout_data["commands"]
            total_commands = len(commands)
            completed_commands = len([c for c in commands if c.status == "completed"])
            failed_commands = len([c for c in commands if c.status == "failed"])
            
            # Calculate status
            if completed_commands == total_commands:
                status = "completed"
            elif failed_commands > 0:
                status = "partial_failure"
            elif any(c.status in ["running", "sent"] for c in commands):
                status = "in_progress"
            else:
                status = "pending"
            
            # Get patches from command results
            patches = []
            for command in commands[:5]:  # Limit to first 5 for display
                if command.result and command.result.get("patches_installed", 0) > 0:
                    patch = PatchResponse(
                        id=f"{command.command_id}_patch",
                        patch_id=f"KB{command.created_at.strftime('%Y%m%d')}",
                        title="Windows Security Update",
                        description="Security and reliability improvements",
                        severity="important",
                        category="security",
                        target_os="Windows",
                        created_at=command.created_at,
                        status="installed" if command.status == "completed" else command.status
                    )
                    patches.append(patch)
            
            rollout = PatchRolloutResponse(
                id=rollout_data["id"],
                name=rollout_data["name"],
                patches=patches,
                target_tags=rollout_data["target_tags"],
                strategy=rollout_data["strategy"],
                status=status,
                created_at=rollout_data["created_at"],
                progress=(completed_commands / total_commands * 100) if total_commands > 0 else 0,
                total_agents=total_commands,
                completed_agents=completed_commands,
                success_rate=(completed_commands / total_commands * 100) if total_commands > 0 else 0,
                success_threshold=95,
                rollback_on_failure=True,
                auto_promote=False
            )
            rollouts.append(rollout)
        
        return rollouts
        
    except Exception as e:
        logger.error("Failed to get rollouts from commands", error=str(e))
        return []


# Patch Rollouts
@router.post("/patch-rollouts", response_model=PatchRolloutResponse)
async def create_rollout(
    rollout_data: RolloutCreate,
    db: AsyncSession = Depends(get_db_session)
):
    """Create a new patch rollout"""
    try:
        from ..db.crud import list_agents, create_command
        from ..ws.connection_manager import connection_manager
        
        # Get target agents based on tags
        all_agents = await list_agents(db=db, limit=1000)
        target_agents = []
        
        if rollout_data.target_tags:
            for agent in all_agents:
                if agent.tags and any(tag in agent.tags for tag in rollout_data.target_tags):
                    target_agents.append(agent)
        else:
            target_agents = all_agents
        
        if not target_agents:
            raise HTTPException(status_code=400, detail="No agents match the specified tags")
        
        # Create patch commands for target agents
        rollout_id = f"rollout_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        successful_commands = []
        failed_commands = []
        
        for agent in target_agents:
            try:
                command_payload = {
                    "rollout_id": rollout_id,
                    "strategy": rollout_data.strategy,
                    "check_version": True,
                    "auto_update": True
                }
                
                expires_at = datetime.utcnow() + timedelta(days=7)  # 7 day expiry for patches
                command = await create_command(
                    db=db,
                    agent_id=agent.agent_id,
                    command_type="patch",
                    payload=command_payload,
                    signature="",
                    created_by="admin",
                    expires_at=expires_at,
                    priority=4
                )
                
                # Send command to agent if online
                if agent.agent_id in connection_manager.agent_connections:
                    command_message = {
                        "type": "command",
                        "command_id": command.command_id,
                        "command_type": "patch",
                        "payload": command_payload,
                        "expires_at": expires_at.isoformat()
                    }
                    
                    success = await connection_manager.send_command(agent.agent_id, command_message)
                    if success:
                        successful_commands.append(command)
                        from ..db.crud import update_command_status
                        await update_command_status(db, command.command_id, "sent")
                    else:
                        failed_commands.append({"agent_id": agent.agent_id, "error": "Failed to send command"})
                else:
                    # Agent offline, command will be delivered when online
                    successful_commands.append(command)
                    
            except Exception as e:
                logger.error("Failed to create patch command", agent_id=agent.agent_id, error=str(e))
                failed_commands.append({"agent_id": agent.agent_id, "error": str(e)})
        
        # Create rollout response
        rollout = PatchRolloutResponse(
            id=rollout_id,
            name=rollout_data.name,
            patches=[],  # Will be populated as patches are installed
            target_tags=rollout_data.target_tags,
            strategy=rollout_data.strategy,
            canary_percentage=rollout_data.canary_percentage,
            canary_wait_time=rollout_data.canary_wait_time,
            status="pending",
            created_at=datetime.utcnow(),
            progress=0.0,
            total_agents=len(target_agents),
            completed_agents=0,
            success_threshold=rollout_data.success_threshold,
            rollback_on_failure=rollout_data.rollback_on_failure,
            auto_promote=rollout_data.auto_promote
        )
        
        logger.info("Patch rollout created", 
                   rollout_id=rollout_id, 
                   target_agents=len(target_agents),
                   successful_commands=len(successful_commands))
        
        return rollout
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to create rollout", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create patch rollout")


@router.get("/patch-rollouts", response_model=PaginatedRollouts)
async def get_rollouts(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db_session)
):
    """Get all patch rollouts"""
    try:
        # Get rollouts from command patterns
        all_rollouts = await get_rollouts_from_commands(db)
        
        # Apply status filter
        filtered_rollouts = all_rollouts
        if status:
            filtered_rollouts = [r for r in filtered_rollouts if r.status == status]
        
        # Apply pagination
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_rollouts = filtered_rollouts[start_idx:end_idx]
        
        total = len(filtered_rollouts)
        pages = (total + per_page - 1) // per_page
        
        return PaginatedRollouts(
            items=paginated_rollouts,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
        
    except Exception as e:
        logger.error("Failed to get rollouts", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve patch rollouts")


@router.post("/patch-rollouts/{rollout_id}/pause", response_model=PatchRolloutResponse)
async def pause_rollout(
    rollout_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """Pause a rollout"""
    try:
        # Get rollout commands and update their status
        from ..db.crud import get_commands_by_type, update_command_status
        
        # Find commands for this rollout
        all_commands = await get_commands_by_type(db=db, command_type="patch", limit=1000)
        rollout_commands = [
            cmd for cmd in all_commands 
            if cmd.payload and cmd.payload.get("rollout_id") == rollout_id
        ]
        
        if not rollout_commands:
            raise HTTPException(status_code=404, detail="Rollout not found")
        
        # Pause pending commands
        paused_count = 0
        for command in rollout_commands:
            if command.status in ["pending", "sent"]:
                await update_command_status(db, command.command_id, "paused")
                paused_count += 1
        
        # Return updated rollout status
        rollouts = await get_rollouts_from_commands(db)
        rollout = next((r for r in rollouts if r.id == rollout_id), None)
        
        if rollout:
            rollout.status = "paused"
            return rollout
        else:
            raise HTTPException(status_code=404, detail="Rollout not found")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to pause rollout", rollout_id=rollout_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to pause rollout")


@router.post("/patch-rollouts/{rollout_id}/resume", response_model=PatchRolloutResponse)
async def resume_rollout(
    rollout_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """Resume a rollout"""
    try:
        from ..db.crud import get_commands_by_type, update_command_status
        from ..ws.connection_manager import connection_manager
        
        # Find commands for this rollout
        all_commands = await get_commands_by_type(db=db, command_type="patch", limit=1000)
        rollout_commands = [
            cmd for cmd in all_commands 
            if cmd.payload and cmd.payload.get("rollout_id") == rollout_id
        ]
        
        if not rollout_commands:
            raise HTTPException(status_code=404, detail="Rollout not found")
        
        # Resume paused commands
        resumed_count = 0
        for command in rollout_commands:
            if command.status == "paused":
                await update_command_status(db, command.command_id, "pending")
                
                # Try to send to agent if online
                agent_id = command.agent.agent_id if command.agent else None
                if agent_id and agent_id in connection_manager.agent_connections:
                    command_message = {
                        "type": "command",
                        "command_id": command.command_id,
                        "command_type": "patch",
                        "payload": command.payload,
                        "expires_at": command.expires_at.isoformat()
                    }
                    
                    await connection_manager.send_command(agent_id, command_message)
                    await update_command_status(db, command.command_id, "sent")
                
                resumed_count += 1
        
        # Return updated rollout status
        rollouts = await get_rollouts_from_commands(db)
        rollout = next((r for r in rollouts if r.id == rollout_id), None)
        
        if rollout:
            rollout.status = "in_progress"
            return rollout
        else:
            raise HTTPException(status_code=404, detail="Rollout not found")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to resume rollout", rollout_id=rollout_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to resume rollout")


@router.post("/patch-rollouts/{rollout_id}/rollback", response_model=PatchRolloutResponse)
async def rollback_rollout(
    rollout_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """Rollback a rollout"""
    try:
        from ..db.crud import get_commands_by_type, update_command_status, create_command
        from ..ws.connection_manager import connection_manager
        
        # Find commands for this rollout
        all_commands = await get_commands_by_type(db=db, command_type="patch", limit=1000)
        rollout_commands = [
            cmd for cmd in all_commands 
            if cmd.payload and cmd.payload.get("rollout_id") == rollout_id
        ]
        
        if not rollout_commands:
            raise HTTPException(status_code=404, detail="Rollout not found")
        
        # Cancel pending commands and create rollback commands for completed ones
        rollback_count = 0
        for command in rollout_commands:
            if command.status in ["pending", "sent", "running"]:
                # Cancel pending commands
                await update_command_status(db, command.command_id, "cancelled", error_message="Rollout cancelled")
                rollback_count += 1
            elif command.status == "completed":
                # Create rollback command for completed patches
                try:
                    rollback_payload = {
                        "rollout_id": f"{rollout_id}_rollback",
                        "action": "rollback",
                        "original_command_id": command.command_id
                    }
                    
                    expires_at = datetime.utcnow() + timedelta(days=1)
                    rollback_command = await create_command(
                        db=db,
                        agent_id=command.agent.agent_id if command.agent else "unknown",
                        command_type="patch_rollback",
                        payload=rollback_payload,
                        signature="",
                        created_by="admin",
                        expires_at=expires_at,
                        priority=2  # High priority for rollbacks
                    )
                    
                    # Send rollback command if agent is online
                    agent_id = command.agent.agent_id if command.agent else None
                    if agent_id and agent_id in connection_manager.agent_connections:
                        rollback_message = {
                            "type": "command",
                            "command_id": rollback_command.command_id,
                            "command_type": "patch_rollback",
                            "payload": rollback_payload,
                            "expires_at": expires_at.isoformat()
                        }
                        
                        await connection_manager.send_command(agent_id, rollback_message)
                        await update_command_status(db, rollback_command.command_id, "sent")
                    
                    rollback_count += 1
                    
                except Exception as e:
                    logger.error("Failed to create rollback command", command_id=command.command_id, error=str(e))
        
        # Return updated rollout status
        rollouts = await get_rollouts_from_commands(db)
        rollout = next((r for r in rollouts if r.id == rollout_id), None)
        
        if rollout:
            rollout.status = "rolled_back"
            return rollout
        else:
            raise HTTPException(status_code=404, detail="Rollout not found")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to rollback rollout", rollout_id=rollout_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to rollback rollout")