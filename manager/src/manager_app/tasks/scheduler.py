"""
Scheduled task execution and management
"""

import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any

from celery import current_task
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from .celery_app import celery_app
from .command_delivery import broadcast_command_to_agents
from ..db.database import get_async_db_session
from ..db.crud import list_active_schedules, get_agents_by_tags

logger = structlog.get_logger()


@celery_app.task
def process_scheduled_scans():
    """
    Process scheduled scan tasks that are due for execution
    """
    
    async def _process_scheduled_scans():
        async with get_async_db_session() as db:
            try:
                # Get active schedules that are due
                current_time = datetime.utcnow()
                # This would need to be implemented in CRUD
                # due_schedules = await get_due_schedules(db, current_time)
                
                executed_count = 0
                # for schedule in due_schedules:
                #     await execute_scheduled_task(schedule)
                #     executed_count += 1
                
                logger.info("Processed scheduled scans", count=executed_count)
                return {"executed": executed_count}
                
            except Exception as e:
                logger.error("Failed to process scheduled scans", error=str(e))
                return {"error": str(e)}
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_process_scheduled_scans())
    finally:
        loop.close()


@celery_app.task
def execute_scan_schedule(schedule_id: str):
    """
    Execute a specific scan schedule
    
    Args:
        schedule_id: UUID of schedule to execute
        
    Returns:
        dict: Execution result
    """
    
    async def _execute_scan_schedule():
        async with get_async_db_session() as db:
            try:
                from ..db.crud import get_schedule_by_id
                
                # Get schedule details
                schedule = await get_schedule_by_id(db, schedule_id)
                if not schedule:
                    return {"status": "error", "message": "Schedule not found"}
                
                if not schedule.enabled:
                    return {"status": "skipped", "message": "Schedule disabled"}
                
                # Prepare scan command
                scan_command = {
                    "command_type": "scan",
                    "payload": {
                        "scan_type": schedule.command_payload.get("scan_type", "full"),
                        "targets": schedule.command_payload.get("targets", []),
                        "options": schedule.command_payload.get("options", {}),
                        "schedule_id": schedule_id,
                        "scheduled_at": datetime.utcnow().isoformat()
                    },
                    "priority": 3,  # Scheduled scans have medium priority
                    "ttl_minutes": 240  # 4 hour TTL for scheduled scans
                }
                
                # Get target agents
                target_agents = []
                if schedule.target_agents:
                    target_agents = schedule.target_agents
                elif schedule.target_tags:
                    # Get agents with matching tags
                    tagged_agents = await get_agents_by_tags(db, schedule.target_tags)
                    target_agents = [agent.agent_id for agent in tagged_agents]
                
                if not target_agents:
                    logger.warning("No target agents found for schedule", 
                                  schedule_id=schedule_id)
                    return {"status": "warning", "message": "No target agents"}
                
                # Broadcast scan command
                result = broadcast_command_to_agents.apply_async(
                    args=[scan_command, target_agents]
                )
                
                logger.info("Scan schedule executed", 
                           schedule_id=schedule_id,
                           target_count=len(target_agents),
                           task_id=result.id)
                
                return {
                    "status": "success",
                    "target_agents": len(target_agents),
                    "broadcast_task_id": result.id
                }
                
            except Exception as e:
                logger.error("Failed to execute scan schedule", 
                            schedule_id=schedule_id, error=str(e))
                return {"status": "error", "error": str(e)}
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_execute_scan_schedule())
    finally:
        loop.close()


@celery_app.task
def execute_patch_rollout(rollout_id: str, phase: str = "canary"):
    """
    Execute patch rollout with canary deployment
    
    Args:
        rollout_id: UUID of patch rollout
        phase: Rollout phase (canary, partial, full)
        
    Returns:
        dict: Rollout execution result
    """
    
    async def _execute_patch_rollout():
        async with get_async_db_session() as db:
            try:
                from ..db.crud import get_patch_rollout_by_id
                
                # Get rollout details
                rollout = await get_patch_rollout_by_id(db, rollout_id)
                if not rollout:
                    return {"status": "error", "message": "Rollout not found"}
                
                # Calculate target agents based on phase
                all_targets = rollout.target_agents or []
                
                if phase == "canary":
                    # 5% of agents for canary
                    target_count = max(1, len(all_targets) // 20)
                    target_agents = all_targets[:target_count]
                elif phase == "partial":
                    # 25% of agents for partial rollout
                    target_count = max(1, len(all_targets) // 4)
                    target_agents = all_targets[:target_count]
                else:  # full
                    target_agents = all_targets
                
                # Prepare patch command
                patch_command = {
                    "command_type": "patch",
                    "payload": {
                        "patch_ids": rollout.patch_ids,
                        "rollout_id": rollout_id,
                        "phase": phase,
                        "install_options": rollout.rollout_config.get("install_options", {}),
                        "reboot_required": rollout.rollout_config.get("reboot_required", False),
                        "rollback_on_failure": rollout.rollout_config.get("rollback_on_failure", True)
                    },
                    "priority": 2,  # High priority for patches
                    "ttl_minutes": 480  # 8 hour TTL for patch installation
                }
                
                # Broadcast patch command
                result = broadcast_command_to_agents.apply_async(
                    args=[patch_command, target_agents]
                )
                
                logger.info("Patch rollout executed", 
                           rollout_id=rollout_id,
                           phase=phase,
                           target_count=len(target_agents),
                           task_id=result.id)
                
                return {
                    "status": "success",
                    "phase": phase,
                    "target_agents": len(target_agents),
                    "broadcast_task_id": result.id
                }
                
            except Exception as e:
                logger.error("Failed to execute patch rollout", 
                            rollout_id=rollout_id, error=str(e))
                return {"status": "error", "error": str(e)}
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_execute_patch_rollout())
    finally:
        loop.close()


@celery_app.task
def schedule_agent_maintenance(agent_ids: List[str], maintenance_type: str):
    """
    Schedule maintenance tasks for agents
    
    Args:
        agent_ids: List of agent IDs
        maintenance_type: Type of maintenance (update, restart, cleanup)
        
    Returns:
        dict: Maintenance scheduling result
    """
    
    maintenance_commands = {
        "update": {
            "command_type": "update_agent",
            "payload": {"check_version": True, "auto_update": True},
            "priority": 4,
            "ttl_minutes": 120
        },
        "restart": {
            "command_type": "restart_agent",
            "payload": {"graceful": True, "delay_seconds": 30},
            "priority": 3,
            "ttl_minutes": 60
        },
        "cleanup": {
            "command_type": "cleanup",
            "payload": {"clear_logs": True, "clear_cache": True},
            "priority": 5,
            "ttl_minutes": 180
        }
    }
    
    if maintenance_type not in maintenance_commands:
        return {"status": "error", "message": "Invalid maintenance type"}
    
    command_data = maintenance_commands[maintenance_type]
    
    # Broadcast maintenance command
    result = broadcast_command_to_agents.apply_async(
        args=[command_data, agent_ids]
    )
    
    logger.info("Agent maintenance scheduled", 
               maintenance_type=maintenance_type,
               agent_count=len(agent_ids),
               task_id=result.id)
    
    return {
        "status": "success",
        "maintenance_type": maintenance_type,
        "agent_count": len(agent_ids),
        "broadcast_task_id": result.id
    }