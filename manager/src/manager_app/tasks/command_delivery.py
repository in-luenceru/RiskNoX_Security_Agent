"""
Command delivery tasks for Celery background processing
"""

import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any

from celery import current_task
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from .celery_app import celery_app
from ..db.database import get_async_db_session
from ..db.crud import get_command_by_id, update_command_status, list_pending_commands
from ..ws.connection_manager import connection_manager
from ..security.signer import sign_command_payload

logger = structlog.get_logger()


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def deliver_command(self, command_id: str):
    """
    Deliver command to agent via WebSocket or queue for polling
    
    Args:
        command_id: UUID of command to deliver
    
    Returns:
        dict: Delivery result with status and details
    """
    
    async def _deliver_command():
        async with get_async_db_session() as db:
            try:
                # Get command from database
                command = await get_command_by_id(db, command_id)
                if not command:
                    logger.error("Command not found", command_id=command_id)
                    return {"status": "error", "message": "Command not found"}
                
                # Check if command is already processed or expired
                if command.status in ["completed", "failed", "cancelled"]:
                    logger.info("Command already processed", 
                               command_id=command_id, status=command.status)
                    return {"status": "skipped", "message": f"Already {command.status}"}
                
                if command.expires_at and command.expires_at < datetime.utcnow():
                    await update_command_status(db, command_id, "expired")
                    logger.warning("Command expired", command_id=command_id)
                    return {"status": "expired", "message": "Command expired"}
                
                # Prepare command message
                command_message = {
                    "type": "command",
                    "command_id": command.command_id,
                    "command_type": command.command_type,
                    "payload": command.payload,
                    "priority": command.priority,
                    "issued_at": command.created_at.isoformat(),
                    "expires_at": command.expires_at.isoformat() if command.expires_at else None
                }
                
                # Add signature
                signature = sign_command_payload(command_message)
                if signature:
                    command_message["signature"] = signature
                    command_message["signed_by"] = "manager"
                
                # Try WebSocket delivery first
                agent_id = command.agent.agent_id if command.agent else None
                if agent_id:
                    success = await connection_manager.send_command(agent_id, command_message)
                    if success:
                        await update_command_status(db, command_id, "sent", sent_at=datetime.utcnow())
                        logger.info("Command delivered via WebSocket", 
                                   command_id=command_id, agent_id=agent_id)
                        return {"status": "delivered", "method": "websocket"}
                
                # WebSocket delivery failed, command will be available via polling
                await update_command_status(db, command_id, "pending")
                logger.info("Command queued for polling", 
                           command_id=command_id, agent_id=agent_id)
                return {"status": "queued", "method": "polling"}
                
            except Exception as e:
                logger.error("Command delivery failed", 
                            command_id=command_id, error=str(e))
                await update_command_status(db, command_id, "failed", 
                                          error_message=str(e))
                
                # Retry on transient failures
                if self.request.retries < self.max_retries:
                    raise self.retry(countdown=60 * (2 ** self.request.retries))
                
                return {"status": "failed", "error": str(e)}
    
    # Run async function
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_deliver_command())
    finally:
        loop.close()


@celery_app.task(bind=True)
def batch_deliver_commands(self, command_ids: List[str]):
    """
    Deliver multiple commands in batch
    
    Args:
        command_ids: List of command UUIDs to deliver
        
    Returns:
        dict: Batch delivery results
    """
    results = {}
    
    for command_id in command_ids:
        try:
            result = deliver_command.apply_async(args=[command_id])
            results[command_id] = {"status": "queued", "task_id": result.id}
        except Exception as e:
            results[command_id] = {"status": "error", "error": str(e)}
            logger.error("Failed to queue command delivery", 
                        command_id=command_id, error=str(e))
    
    logger.info("Batch command delivery queued", count=len(command_ids))
    return results


@celery_app.task
def retry_failed_commands():
    """
    Periodic task to retry failed command deliveries
    """
    
    async def _retry_failed_commands():
        async with get_async_db_session() as db:
            try:
                # Get commands that failed recently and can be retried
                cutoff_time = datetime.utcnow() - timedelta(hours=1)
                
                # This would need to be implemented in CRUD
                # failed_commands = await list_failed_commands_for_retry(db, cutoff_time)
                
                retry_count = 0
                # for command in failed_commands:
                #     if command.retry_count < 3:
                #         deliver_command.apply_async(args=[command.command_id])
                #         retry_count += 1
                
                logger.info("Retried failed commands", count=retry_count)
                return {"retried": retry_count}
                
            except Exception as e:
                logger.error("Failed to retry commands", error=str(e))
                return {"error": str(e)}
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_retry_failed_commands())
    finally:
        loop.close()


@celery_app.task
def broadcast_command_to_agents(command_data: Dict[str, Any], 
                               agent_ids: List[str] = None,
                               tags: List[str] = None):
    """
    Broadcast command to multiple agents
    
    Args:
        command_data: Command payload
        agent_ids: Optional list of specific agent IDs
        tags: Optional list of agent tags to target
        
    Returns:
        dict: Broadcast results
    """
    
    async def _broadcast_command():
        async with get_async_db_session() as db:
            try:
                # Create individual commands for each target agent
                from ..db.crud import create_command
                
                target_agents = agent_ids or []
                
                # TODO: If tags specified, resolve to agent IDs
                # if tags:
                #     tagged_agents = await get_agents_by_tags(db, tags)
                #     target_agents.extend([agent.agent_id for agent in tagged_agents])
                
                created_commands = []
                for agent_id in target_agents:
                    command = await create_command(
                        db=db,
                        agent_id=agent_id,
                        command_type=command_data["command_type"],
                        payload=command_data["payload"],
                        priority=command_data.get("priority", 5),
                        ttl_minutes=command_data.get("ttl_minutes", 60)
                    )
                    created_commands.append(command.command_id)
                
                # Queue delivery tasks
                for command_id in created_commands:
                    deliver_command.apply_async(args=[command_id])
                
                logger.info("Broadcast command created", 
                           command_count=len(created_commands),
                           target_agents=len(target_agents))
                
                return {
                    "status": "success",
                    "commands_created": len(created_commands),
                    "command_ids": created_commands
                }
                
            except Exception as e:
                logger.error("Broadcast command failed", error=str(e))
                return {"status": "error", "error": str(e)}
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_broadcast_command())
    finally:
        loop.close()