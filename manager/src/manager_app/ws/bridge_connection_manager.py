"""
WebSocket Connection Manager Bridge Integration
Extends the existing connection manager to work with the Manager Bridge
"""

from typing import Dict, Any, Optional
import logging
from datetime import datetime

from .connection_manager import ConnectionManager as BaseConnectionManager
from ..bridge import ManagerBridge

logger = logging.getLogger(__name__)


class BridgeEnabledConnectionManager(BaseConnectionManager):
    """
    Enhanced connection manager that integrates with Manager Bridge
    for command delivery and agent status management
    """
    
    def __init__(self):
        super().__init__()
        self.bridge: Optional[ManagerBridge] = None
        
    def set_bridge(self, bridge: ManagerBridge):
        """Set the manager bridge instance"""
        self.bridge = bridge
        logger.info("Manager bridge integrated with connection manager")
    
    async def connect(self, websocket, agent_id: str, certificate_serial: str, db):
        """Enhanced connect that notifies bridge of agent connection"""
        connection = await super().connect(websocket, agent_id, certificate_serial, db)
        
        # Notify bridge that agent is online - deliver queued commands
        if self.bridge:
            try:
                await self.bridge.handle_agent_connect(agent_id)
                logger.info("Bridge notified of agent connection", agent_id=agent_id)
            except Exception as e:
                logger.error("Failed to notify bridge of agent connection", 
                           agent_id=agent_id, error=str(e))
        
        return connection
    
    async def handle_agent_message(self, agent_id: str, message: dict, db):
        """Enhanced message handler that routes command responses to bridge"""
        await super().handle_agent_message(agent_id, message, db)
        
        # Route command-related messages to bridge
        if self.bridge:
            try:
                message_type = message.get("type")
                
                if message_type == "command_ack":
                    # Agent acknowledged command receipt
                    command_id = message.get("command_id")
                    if command_id:
                        await self.bridge.handle_command_ack(command_id, agent_id)
                        logger.debug("Command ACK routed to bridge", 
                                   command_id=command_id, agent_id=agent_id)
                
                elif message_type == "command_result":
                    # Agent finished executing command
                    command_id = message.get("command_id")
                    result = message.get("result", {})
                    if command_id:
                        await self.bridge.handle_command_result(command_id, agent_id, result)
                        logger.debug("Command result routed to bridge", 
                                   command_id=command_id, agent_id=agent_id)
                
            except Exception as e:
                logger.error("Failed to route message to bridge", 
                           agent_id=agent_id, error=str(e))
    
    def is_agent_connected(self, agent_id: str) -> bool:
        """Check if agent is currently connected"""
        connection_id = self.agent_connections.get(agent_id)
        if not connection_id:
            return False
            
        connection = self.connections.get(connection_id)
        return connection is not None and connection.is_alive
    
    async def send_to_agent(self, agent_id: str, message: dict) -> bool:
        """
        Send message to agent via WebSocket
        This is the interface used by the Manager Bridge CommandSender
        """
        try:
            # Format message for WebSocket transmission
            ws_message = {
                "type": message.get("type", "command"),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                **message
            }
            
            # Use existing send_command method
            success = await self.send_command(agent_id, ws_message)
            
            if success:
                logger.debug("Message sent to agent via WebSocket", 
                           agent_id=agent_id, message_type=ws_message.get("type"))
            else:
                logger.warning("Failed to send message to agent", 
                             agent_id=agent_id, message_type=ws_message.get("type"))
            
            return success
            
        except Exception as e:
            logger.error("Error sending message to agent", 
                        agent_id=agent_id, error=str(e))
            return False
    
    async def send_command_via_bridge(self, agent_id: str, command_type: str, 
                                    payload: Dict[str, Any], issued_by: str = "admin") -> str:
        """
        Send command via bridge (convenience method for direct use)
        
        Args:
            agent_id: Target agent ID
            command_type: Command type from bridge translator
            payload: Command payload
            issued_by: User who issued the command
            
        Returns:
            Command ID for tracking
        """
        if not self.bridge:
            raise RuntimeError("Manager bridge not configured")
        
        return await self.bridge.sender.send_command_to_agent(
            agent_id=agent_id,
            command_type=command_type,
            payload=payload,
            issued_by=issued_by
        )
    
    async def get_agent_status_for_ui(self, agent_id: str) -> Dict[str, Any]:
        """
        Get comprehensive agent status for UI display
        Combines connection status with command queue status
        """
        is_connected = self.is_agent_connected(agent_id)
        
        # Get command stats from bridge if available
        command_stats = {}
        if self.bridge:
            try:
                command_stats = await self.bridge.get_agent_command_stats(agent_id)
            except Exception as e:
                logger.warning("Failed to get command stats", agent_id=agent_id, error=str(e))
        
        # Get connection details
        connection_details = {}
        if is_connected:
            connection_id = self.agent_connections.get(agent_id)
            if connection_id and connection_id in self.connections:
                connection = self.connections[connection_id]
                connection_details = {
                    "connected_at": connection.connected_at.isoformat(),
                    "last_heartbeat": connection.last_heartbeat.isoformat(),
                    "connection_id": connection.connection_id
                }
        
        return {
            "agent_id": agent_id,
            "is_connected": is_connected,
            "status": "online" if is_connected else "offline",
            "connection_details": connection_details,
            "command_stats": command_stats,
            "queued_messages": len(self.offline_message_queue.get(agent_id, [])),
            "last_updated": datetime.utcnow().isoformat() + "Z"
        }
    
    async def broadcast_admin_action(self, agent_ids: list, action: str, 
                                   payload: Dict[str, Any], issued_by: str = "admin") -> Dict[str, Any]:
        """
        Broadcast admin action to multiple agents via bridge
        
        Args:
            agent_ids: List of target agent IDs
            action: Action type (from bridge translator)
            payload: Action payload
            issued_by: User who issued the action
            
        Returns:
            Results dict with per-agent results
        """
        if not self.bridge:
            raise RuntimeError("Manager bridge not configured")
        
        return await self.bridge.execute_bulk_action(
            agent_ids=agent_ids,
            action=action,
            payload=payload,
            issued_by=issued_by
        )
    
    async def get_fleet_status(self) -> Dict[str, Any]:
        """Get overall fleet status for dashboard"""
        total_agents = len(self.agent_connections)
        online_agents = sum(1 for agent_id in self.agent_connections.keys() 
                           if self.is_agent_connected(agent_id))
        offline_agents = total_agents - online_agents
        
        # Get command statistics from bridge
        total_pending_commands = 0
        total_queued_commands = 0
        
        if self.bridge:
            try:
                for agent_id in self.agent_connections.keys():
                    stats = await self.bridge.get_agent_command_stats(agent_id)
                    total_pending_commands += stats.get("pending", 0) + stats.get("sent", 0)
                    total_queued_commands += stats.get("queued", 0)
            except Exception as e:
                logger.warning("Failed to get fleet command stats", error=str(e))
        
        return {
            "total_agents": total_agents,
            "online_agents": online_agents,
            "offline_agents": offline_agents,
            "pending_commands": total_pending_commands,
            "queued_commands": total_queued_commands,
            "last_updated": datetime.utcnow().isoformat() + "Z"
        }
    
    async def start_bridge_background_tasks(self):
        """Start bridge-related background tasks"""
        if self.bridge:
            # Start periodic cleanup and retry tasks
            import asyncio
            
            async def periodic_bridge_maintenance():
                while True:
                    try:
                        await self.bridge.cleanup_expired_commands()
                        await self.bridge.retry_failed_commands()
                        await asyncio.sleep(60)  # Run every minute
                    except Exception as e:
                        logger.error("Bridge maintenance task failed", error=str(e))
                        await asyncio.sleep(60)
            
            asyncio.create_task(periodic_bridge_maintenance())
            logger.info("Started bridge maintenance background tasks")


# Factory function for dependency injection
def create_bridge_enabled_connection_manager() -> BridgeEnabledConnectionManager:
    """Create a bridge-enabled connection manager instance"""
    return BridgeEnabledConnectionManager()


# Integration helper for existing FastAPI dependency
async def get_bridge_connection_manager() -> BridgeEnabledConnectionManager:
    """
    Dependency to get bridge-enabled connection manager
    This replaces the existing get_connection_manager dependency
    """
    # In production, this would be a singleton injected by the FastAPI app
    # For now, create a new instance
    return create_bridge_enabled_connection_manager()