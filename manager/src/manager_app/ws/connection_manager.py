"""
WebSocket Connection Manager for Agent Communications
Handles mTLS WebSocket connections, message routing, and connection lifecycle
"""

import asyncio
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from collections import defaultdict

from fastapi import WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from ..db.crud import update_agent_connection_status, get_agent_by_certificate_serial
from ..security.signer import verify_command_signature, sign_message

logger = structlog.get_logger()


class AgentConnection:
    """Represents a single agent WebSocket connection"""
    
    def __init__(self, websocket: WebSocket, agent_id: str, certificate_serial: str):
        self.websocket = websocket
        self.agent_id = agent_id
        self.certificate_serial = certificate_serial
        self.connection_id = str(uuid.uuid4())
        self.connected_at = datetime.utcnow()
        self.last_heartbeat = datetime.utcnow()
        self.is_alive = True
        
    async def send_message(self, message: dict) -> bool:
        """Send message to agent with error handling"""
        try:
            # Sign the message for integrity
            signed_message = sign_message(message)
            await self.websocket.send_text(json.dumps(signed_message))
            return True
        except Exception as e:
            logger.error("Failed to send message to agent", 
                        agent_id=self.agent_id, error=str(e))
            self.is_alive = False
            return False
            
    def update_heartbeat(self):
        """Update last heartbeat timestamp"""
        self.last_heartbeat = datetime.utcnow()
        
    def is_connection_stale(self, timeout_seconds: int = 300) -> bool:
        """Check if connection is stale based on heartbeat"""
        return (datetime.utcnow() - self.last_heartbeat).total_seconds() > timeout_seconds


class ConnectionManager:
    """Manages all agent WebSocket connections"""
    
    def __init__(self):
        # Active connections: connection_id -> AgentConnection
        self.connections: Dict[str, AgentConnection] = {}
        
        # Agent mappings: agent_id -> connection_id
        self.agent_connections: Dict[str, str] = {}
        
        # Connection groups for broadcast
        self.connection_groups: Dict[str, Set[str]] = defaultdict(set)
        
        # Message queue for offline agents
        self.offline_message_queue: Dict[str, List[dict]] = defaultdict(list)
        
        # Background tasks
        self._cleanup_task = None
        self._heartbeat_task = None
        
    async def start_background_tasks(self):
        """Start background maintenance tasks"""
        if not self._cleanup_task:
            self._cleanup_task = asyncio.create_task(self._cleanup_stale_connections())
        if not self._heartbeat_task:
            self._heartbeat_task = asyncio.create_task(self._send_heartbeats())
            
    async def connect(self, websocket: WebSocket, agent_id: str, 
                     certificate_serial: str, db: AsyncSession) -> AgentConnection:
        """Register new agent connection"""
        # Close existing connection if any
        await self.disconnect(agent_id)
        
        # Create new connection
        connection = AgentConnection(websocket, agent_id, certificate_serial)
        
        # Store connection mappings
        self.connections[connection.connection_id] = connection
        self.agent_connections[agent_id] = connection.connection_id
        
        # Update agent status in database
        await update_agent_connection_status(
            db, agent_id, "active", datetime.utcnow()
        )
        
        # Send welcome message
        welcome_message = {
            "type": "welcome",
            "connection_id": connection.connection_id,
            "server_time": datetime.utcnow().isoformat(),
            "heartbeat_interval": 30
        }
        await connection.send_message(welcome_message)
        
        # Broadcast agent connection to UI
        try:
            from ..socketio_server import sio
            await sio.emit('agent_connected', {
                'agent_id': agent_id,
                'timestamp': datetime.utcnow().isoformat()
            })
            
            # Create connection event
            from ..db.crud import create_event
            await create_event(
                db=db,
                event_type="agent_connected",
                event_data={"message": f"Agent {agent_id} connected successfully"},
                source="manager",
                agent_id=agent_id,
                severity="info"
            )
        except Exception as e:
            logger.warning("Failed to broadcast agent connection", error=str(e))            # Send queued messages
            await self._send_queued_messages(agent_id)
            
            logger.info("Agent connected via WebSocket", 
                       agent_id=agent_id, 
                       connection_id=connection.connection_id)
            
            return connection
            
        except Exception as e:
            logger.error("Failed to register agent connection", 
                        agent_id=agent_id, error=str(e))
            raise
            
    async def disconnect(self, agent_id: str, db: Optional[AsyncSession] = None):
        """Disconnect agent and cleanup"""
        try:
            connection_id = self.agent_connections.get(agent_id)
            if not connection_id:
                return
                
            connection = self.connections.get(connection_id)
            if connection:
                try:
                    # Send disconnect message
                    disconnect_msg = {
                        "type": "disconnect",
                        "reason": "server_initiated",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    await connection.send_message(disconnect_msg)
                    await connection.websocket.close()
                except:
                    pass  # Connection might already be closed
                    
                # Remove from all mappings
                del self.connections[connection_id]
                del self.agent_connections[agent_id]
                
                # Remove from groups
                for group_connections in self.connection_groups.values():
                    group_connections.discard(connection_id)
                    
            # Update database status
            if db:
                await update_agent_connection_status(db, agent_id, "inactive", None)
                
                # Broadcast agent disconnection to UI
                try:
                    from ..socketio_server import sio
                    await sio.emit('agent_disconnected', {
                        'agent_id': agent_id,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    # Create disconnection event
                    from ..db.crud import create_event
                    await create_event(
                        db=db,
                        event_type="agent_disconnected", 
                        event_data={"message": f"Agent {agent_id} disconnected"},
                        source="manager",
                        agent_id=agent_id,
                        severity="info"
                    )
                except Exception as e:
                    logger.warning("Failed to broadcast agent disconnection", error=str(e))
                
            logger.info("Agent disconnected", agent_id=agent_id)
            
        except Exception as e:
            logger.error("Error during agent disconnect", 
                        agent_id=agent_id, error=str(e))
            
    async def send_command(self, agent_id: str, command: dict) -> bool:
        """Send command to specific agent"""
        connection_id = self.agent_connections.get(agent_id)
        if not connection_id:
            # Queue message for offline agent
            self.offline_message_queue[agent_id].append(command)
            logger.warning("Agent offline, queued command", 
                          agent_id=agent_id, command_type=command.get("type"))
            return False
            
        connection = self.connections.get(connection_id)
        if not connection or not connection.is_alive:
            # Connection stale, queue message
            self.offline_message_queue[agent_id].append(command)
            await self.disconnect(agent_id)
            return False
            
        success = await connection.send_message(command)
        if not success:
            # Failed to send, queue for retry
            self.offline_message_queue[agent_id].append(command)
            await self.disconnect(agent_id)
            
        return success
        
    async def broadcast_command(self, command: dict, 
                               agent_ids: Optional[List[str]] = None,
                               tags: Optional[List[str]] = None) -> Dict[str, bool]:
        """Broadcast command to multiple agents"""
        results = {}
        
        target_agents = agent_ids or list(self.agent_connections.keys())
        
        # TODO: Filter by tags if specified
        
        for agent_id in target_agents:
            results[agent_id] = await self.send_command(agent_id, command)
            
        return results
        
    async def handle_agent_message(self, agent_id: str, message: dict, 
                                  db: AsyncSession):
        """Process message received from agent"""
        try:
            message_type = message.get("type")
            
            if message_type == "heartbeat":
                await self._handle_heartbeat(agent_id)
            elif message_type == "command_result":
                await self._handle_command_result(agent_id, message, db)
            elif message_type == "event":
                await self._handle_agent_event(agent_id, message, db)
            elif message_type == "status_update":
                await self._handle_status_update(agent_id, message, db)
            elif message_type == "scan_logs":
                await self._handle_scan_logs(agent_id, message)
            else:
                logger.warning("Unknown message type from agent", 
                              agent_id=agent_id, message_type=message_type)
                              
        except Exception as e:
            logger.error("Error handling agent message", 
                        agent_id=agent_id, error=str(e))
            
    async def _handle_heartbeat(self, agent_id: str):
        """Handle agent heartbeat"""
        connection_id = self.agent_connections.get(agent_id)
        if connection_id and connection_id in self.connections:
            self.connections[connection_id].update_heartbeat()
            
    async def _handle_command_result(self, agent_id: str, message: dict, db: AsyncSession):
        """Handle command execution result from agent"""
        from ..db.crud import update_command_result
        
        command_id = message.get("command_id")
        result = message.get("result")
        error = message.get("error")
        status = "completed" if not error else "failed"
        
        if command_id:
            await update_command_result(db, command_id, status, result, error)
            logger.info("Command result received", 
                       agent_id=agent_id, command_id=command_id, status=status)
            
            # Broadcast command update to UI
            try:
                from ..socketio_server import sio
                await sio.emit('command_update', {
                    'command_id': command_id,
                    'agent_id': agent_id,
                    'status': status,
                    'result': result,
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                # If this is a scan result, broadcast scan update
                if result and result.get('scan_type'):
                    await sio.emit('scan_update', {
                        'scan_id': command_id,
                        'agent_id': agent_id,
                        'status': status,
                        'files_scanned': result.get('files_scanned', 0),
                        'threats_found': result.get('threats_found', 0),
                        'timestamp': datetime.utcnow().isoformat()
                    })
            except Exception as e:
                logger.warning("Failed to broadcast command update", error=str(e))
            
    async def _handle_agent_event(self, agent_id: str, message: dict, db: AsyncSession):
        """Handle agent event (scan results, etc.)"""
        from ..db.crud import create_event
        
        event_data = {
            "agent_id": agent_id,
            "event_type": message.get("event_type", "unknown"),
            "event_data": message.get("data", {}),
            "severity": message.get("severity", "info"),
            "timestamp": datetime.utcnow()
        }
        
        await create_event(db, event_data)
        logger.info("Agent event received", 
                   agent_id=agent_id, event_type=event_data["event_type"])
        
    async def _handle_status_update(self, agent_id: str, message: dict, db: AsyncSession):
        """Handle agent status update"""
        from ..db.crud import update_agent_metadata
        
        status_data = message.get("status", {})
        await update_agent_metadata(db, agent_id, {"last_status": status_data})
    
    async def _handle_scan_logs(self, agent_id: str, message: dict):
        """Handle real-time scan logs from agent"""
        try:
            from ..socketio_server import sio
            scan_id = message.get("scan_id")
            log_line = message.get("log_line")
            progress = message.get("progress", 0)
            files_scanned = message.get("files_scanned", 0)
            threats_found = message.get("threats_found", 0)
            
            if scan_id and log_line:
                # Broadcast to UI
                await sio.emit('scan_logs', {
                    'scan_id': scan_id,
                    'agent_id': agent_id,
                    'log_line': log_line,
                    'progress': progress,
                    'files_scanned': files_scanned,
                    'threats_found': threats_found,
                    'timestamp': message.get("timestamp", datetime.utcnow().isoformat())
                })
                
                # Update command result with progress
                if progress > 0 or files_scanned > 0:
                    from ..db.crud import get_command_by_id, update_command_result
                    from ..db.database import get_db_session
                    
                    # Update scan progress in database
                    try:
                        async with get_db_session() as db:
                            command = await get_command_by_id(db, scan_id)
                            if command and command.command_type == "scan":
                                current_result = command.result or {}
                                current_result.update({
                                    "progress": progress,
                                    "files_scanned": files_scanned,
                                    "threats_found": threats_found,
                                    "last_update": datetime.utcnow().isoformat()
                                })
                                
                                await update_command_result(
                                    db, scan_id, 
                                    "running" if progress < 100 else "completed",
                                    current_result
                                )
                    except Exception as db_error:
                        logger.warning("Failed to update scan progress in DB", error=str(db_error))
                
                logger.debug("Scan log broadcasted", scan_id=scan_id, agent_id=agent_id)
        except Exception as e:
            logger.warning("Failed to broadcast scan logs", error=str(e))
        
    async def _send_queued_messages(self, agent_id: str):
        """Send queued messages when agent comes online"""
        queued_messages = self.offline_message_queue.get(agent_id, [])
        if not queued_messages:
            return
            
        success_count = 0
        for message in queued_messages:
            if await self.send_command(agent_id, message):
                success_count += 1
            else:
                break  # Stop on first failure
                
        # Remove successfully sent messages
        if success_count > 0:
            self.offline_message_queue[agent_id] = queued_messages[success_count:]
            
        logger.info("Sent queued messages", 
                   agent_id=agent_id, sent=success_count, 
                   remaining=len(self.offline_message_queue[agent_id]))
        
    async def _cleanup_stale_connections(self):
        """Background task to clean up stale connections"""
        while True:
            try:
                stale_connections = []
                
                for connection_id, connection in self.connections.items():
                    if connection.is_connection_stale():
                        stale_connections.append(connection.agent_id)
                        
                for agent_id in stale_connections:
                    await self.disconnect(agent_id)
                    
                if stale_connections:
                    logger.info("Cleaned up stale connections", count=len(stale_connections))
                    
            except Exception as e:
                logger.error("Error in connection cleanup", error=str(e))
                
            await asyncio.sleep(60)  # Check every minute
            
    async def _send_heartbeats(self):
        """Background task to send heartbeat requests"""
        while True:
            try:
                heartbeat_msg = {
                    "type": "heartbeat_request",
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                for agent_id in list(self.agent_connections.keys()):
                    await self.send_command(agent_id, heartbeat_msg)
                    
            except Exception as e:
                logger.error("Error sending heartbeats", error=str(e))
                
            await asyncio.sleep(30)  # Send every 30 seconds
            
    def get_connection_stats(self) -> dict:
        """Get connection statistics"""
        return {
            "total_connections": len(self.connections),
            "active_agents": len(self.agent_connections),
            "queued_messages": sum(len(msgs) for msgs in self.offline_message_queue.values()),
            "connection_groups": len(self.connection_groups)
        }


# Global connection manager instance
connection_manager = ConnectionManager()