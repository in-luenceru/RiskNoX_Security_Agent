"""
Socket.IO Server for UI Communications
Provides real-time updates to the admin UI
"""

import socketio
import structlog
from typing import Dict, Any, Optional
import asyncio
from datetime import datetime

from .db.database import get_db_session
from .db.crud import list_agents

logger = structlog.get_logger()

# Create Socket.IO server
sio = socketio.AsyncServer(
    cors_allowed_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
    async_mode='asgi'
)

# Track connected UI clients
ui_clients: Dict[str, Dict[str, Any]] = {}


@sio.event
async def connect(sid, environ, auth):
    """Handle UI client connection"""
    logger.info("UI client connected", client_id=sid)
    ui_clients[sid] = {
        'connected_at': datetime.utcnow().isoformat(),
        'last_activity': datetime.utcnow().isoformat()
    }
    
    # Send initial data to the newly connected client
    try:
        async for db in get_db_session():
            agents = await list_agents(db)
            await sio.emit('agents_update', {
                'agents': [
                    {
                        'agent_id': agent.agent_id,
                        'hostname': agent.hostname,
                        'status': agent.status,
                        'os_type': agent.os_type,
                        'os_version': agent.os_version,
                        'agent_version': agent.agent_version,
                        'ip_address': agent.ip_address,
                        'tags': agent.tags or [],
                        'last_seen_at': agent.last_seen_at.isoformat() if agent.last_seen_at else None,
                        'certificate_expires_at': agent.certificate_expires_at.isoformat(),
                        'created_at': agent.created_at.isoformat()
                    }
                    for agent in agents
                ]
            }, room=sid)
            break  # Only need one iteration
    except Exception as e:
        logger.error("Error sending initial data to UI client", error=str(e), client_id=sid)


@sio.event
async def disconnect(sid):
    """Handle UI client disconnection"""
    logger.info("UI client disconnected", client_id=sid)
    ui_clients.pop(sid, None)


@sio.event
async def ping(sid, data):
    """Handle ping from UI client"""
    ui_clients[sid]['last_activity'] = datetime.utcnow().isoformat()
    await sio.emit('pong', {'timestamp': datetime.utcnow().isoformat()}, room=sid)


# Functions to broadcast updates to all connected UI clients
async def broadcast_agent_update(agent_data: Dict[str, Any]):
    """Broadcast agent status update to all connected UI clients"""
    await sio.emit('agent_status', agent_data)


async def broadcast_command_update(command_data: Dict[str, Any]):
    """Broadcast command status update to all connected UI clients"""
    await sio.emit('command_update', command_data)


async def broadcast_event(event_data: Dict[str, Any]):
    """Broadcast system event to all connected UI clients"""
    await sio.emit('system_event', event_data)


async def broadcast_agents_list():
    """Broadcast updated agents list to all connected UI clients"""
    try:
        async for db in get_db_session():
            agents = await list_agents(db)
            agent_data = {
                'agents': [
                    {
                        'agent_id': agent.agent_id,
                        'hostname': agent.hostname,
                        'status': agent.status,
                        'os_type': agent.os_type,
                        'os_version': agent.os_version,
                        'agent_version': agent.agent_version,
                        'ip_address': agent.ip_address,
                        'tags': agent.tags or [],
                        'last_seen_at': agent.last_seen_at.isoformat() if agent.last_seen_at else None,
                        'certificate_expires_at': agent.certificate_expires_at.isoformat(),
                        'created_at': agent.created_at.isoformat()
                    }
                    for agent in agents
                ]
            }
            await sio.emit('agents_update', agent_data)
            break  # Only need one iteration
    except Exception as e:
        logger.error("Error broadcasting agents list", error=str(e))


# Create ASGI app for Socket.IO
socketio_app = socketio.ASGIApp(sio)