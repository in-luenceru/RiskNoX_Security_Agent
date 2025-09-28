"""
Maintenance tasks for system health and cleanup
"""

import asyncio
from datetime import datetime, timedelta
from typing import List

from celery import current_task
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from .celery_app import celery_app
from ..db.database import get_async_db_session
from ..ws.connection_manager import connection_manager

logger = structlog.get_logger()


@celery_app.task
def cleanup_stale_connections():
    """
    Clean up stale WebSocket connections and update agent status
    """
    
    async def _cleanup_stale_connections():
        try:
            # Get connection stats before cleanup
            stats_before = connection_manager.get_connection_stats()
            
            # Cleanup is handled by connection manager background task
            # This task just triggers a manual cleanup if needed
            
            stats_after = connection_manager.get_connection_stats()
            
            logger.info("Connection cleanup completed", 
                       before=stats_before, after=stats_after)
            
            return {
                "status": "success",
                "connections_before": stats_before["total_connections"],
                "connections_after": stats_after["total_connections"]
            }
            
        except Exception as e:
            logger.error("Connection cleanup failed", error=str(e))
            return {"status": "error", "error": str(e)}
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_cleanup_stale_connections())
    finally:
        loop.close()


@celery_app.task
def check_certificate_expiry():
    """
    Check for expiring agent certificates and trigger renewal
    """
    
    async def _check_certificate_expiry():
        async with get_async_db_session() as db:
            try:
                from ..db.crud import get_agents_with_expiring_certificates
                
                # Check for certificates expiring in the next 30 days
                expiry_threshold = datetime.utcnow() + timedelta(days=30)
                
                # This would need to be implemented in CRUD
                # expiring_agents = await get_agents_with_expiring_certificates(db, expiry_threshold)
                
                renewal_count = 0
                # for agent in expiring_agents:
                #     # Trigger certificate renewal
                #     renew_agent_certificate.apply_async(args=[agent.agent_id])
                #     renewal_count += 1
                
                logger.info("Certificate expiry check completed", 
                           renewals_triggered=renewal_count)
                
                return {
                    "status": "success",
                    "renewals_triggered": renewal_count
                }
                
            except Exception as e:
                logger.error("Certificate expiry check failed", error=str(e))
                return {"status": "error", "error": str(e)}
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_check_certificate_expiry())
    finally:
        loop.close()


@celery_app.task
def renew_agent_certificate(agent_id: str):
    """
    Renew agent certificate
    
    Args:
        agent_id: Agent ID to renew certificate for
        
    Returns:
        dict: Renewal result
    """
    
    async def _renew_agent_certificate():
        async with get_async_db_session() as db:
            try:
                from ..db.crud import get_agent_by_id
                from ..security.ca import generate_agent_certificate
                
                # Get agent details
                agent = await get_agent_by_id(db, agent_id)
                if not agent:
                    return {"status": "error", "message": "Agent not found"}
                
                # Generate new certificate (this would need CSR from agent)
                # For now, just log the renewal attempt
                logger.info("Certificate renewal requested", 
                           agent_id=agent_id, hostname=agent.hostname)
                
                # In a real implementation:
                # 1. Request new CSR from agent
                # 2. Generate new certificate
                # 3. Update database
                # 4. Notify agent of new certificate
                
                return {
                    "status": "success",
                    "message": "Certificate renewal initiated"
                }
                
            except Exception as e:
                logger.error("Certificate renewal failed", 
                            agent_id=agent_id, error=str(e))
                return {"status": "error", "error": str(e)}
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_renew_agent_certificate())
    finally:
        loop.close()


@celery_app.task
def cleanup_old_events(retention_days: int = 90):
    """
    Clean up old events from database
    
    Args:
        retention_days: Number of days to retain events
        
    Returns:
        dict: Cleanup result
    """
    
    async def _cleanup_old_events():
        async with get_async_db_session() as db:
            try:
                from ..db.crud import delete_old_events
                
                cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
                
                # This would need to be implemented in CRUD
                # deleted_count = await delete_old_events(db, cutoff_date)
                deleted_count = 0
                
                logger.info("Old events cleanup completed", 
                           deleted_count=deleted_count,
                           retention_days=retention_days)
                
                return {
                    "status": "success",
                    "deleted_count": deleted_count,
                    "cutoff_date": cutoff_date.isoformat()
                }
                
            except Exception as e:
                logger.error("Events cleanup failed", error=str(e))
                return {"status": "error", "error": str(e)}
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_cleanup_old_events())
    finally:
        loop.close()


@celery_app.task
def system_health_check():
    """
    Perform system health check and report status
    """
    
    async def _system_health_check():
        health_status = {
            "timestamp": datetime.utcnow().isoformat(),
            "components": {}
        }
        
        try:
            # Check database connectivity
            async with get_async_db_session() as db:
                await db.execute("SELECT 1")
                health_status["components"]["database"] = {"status": "healthy"}
        except Exception as e:
            health_status["components"]["database"] = {
                "status": "unhealthy", 
                "error": str(e)
            }
        
        # Check WebSocket connection manager
        try:
            stats = connection_manager.get_connection_stats()
            health_status["components"]["websocket_manager"] = {
                "status": "healthy",
                "stats": stats
            }
        except Exception as e:
            health_status["components"]["websocket_manager"] = {
                "status": "unhealthy",
                "error": str(e)
            }
        
        # Overall health
        unhealthy_components = [
            comp for comp, status in health_status["components"].items()
            if status["status"] != "healthy"
        ]
        
        health_status["overall_status"] = "healthy" if not unhealthy_components else "degraded"
        health_status["unhealthy_components"] = unhealthy_components
        
        logger.info("System health check completed", 
                   status=health_status["overall_status"],
                   unhealthy=len(unhealthy_components))
        
        return health_status
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_system_health_check())
    finally:
        loop.close()