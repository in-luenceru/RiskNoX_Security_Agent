"""
Agent WebSocket Stream Handler
Handles mTLS WebSocket connections from agents
"""

import json
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from ..db.database import get_db_session
from ..db.crud import get_agent_by_certificate_serial, update_agent_connection_status
from .connection_manager import connection_manager

router = APIRouter()
security = HTTPBearer()
logger = structlog.get_logger()


async def verify_agent_certificate(websocket: WebSocket) -> Optional[dict]:
    """
    Verify agent mTLS certificate and extract agent information
    In production, this would extract the client certificate from the TLS layer
    For development, we'll simulate certificate verification
    """
    try:
        # In production, extract client certificate from TLS layer:
        # client_cert = websocket.client.cert
        # For development, we'll check headers or query params
        
        cert_serial = websocket.headers.get("X-Client-Cert-Serial")
        cert_fingerprint = websocket.headers.get("X-Client-Cert-Fingerprint")
        
        if not cert_serial:
            # Try query parameter for development
            cert_serial = websocket.query_params.get("cert_serial")
            
        if not cert_serial:
            logger.warning("No client certificate serial provided")
            return None
            
        return {
            "serial": cert_serial,
            "fingerprint": cert_fingerprint or "dev_fingerprint"
        }
        
    except Exception as e:
        logger.error("Error verifying client certificate", error=str(e))
        return None


@router.websocket("/ws/agent")
async def agent_websocket(
    websocket: WebSocket,
    db: AsyncSession = Depends(get_db_session)
):
    """
    WebSocket endpoint for agent connections with mTLS authentication
    
    Protocol:
    1. Agent connects with mTLS certificate
    2. Server verifies certificate and looks up agent
    3. Bidirectional message exchange:
       - Server -> Agent: commands, configuration updates
       - Agent -> Server: results, events, heartbeats
    """
    
    # Accept WebSocket connection
    await websocket.accept()
    
    agent_id = None
    connection = None
    
    try:
        # Verify mTLS certificate
        cert_info = await verify_agent_certificate(websocket)
        if not cert_info:
            await websocket.close(code=4001, reason="Invalid certificate")
            return
            
        # Look up agent by certificate serial
        agent = await get_agent_by_certificate_serial(db, cert_info["serial"])
        if not agent:
            logger.warning("Unknown agent certificate", serial=cert_info["serial"])
            await websocket.close(code=4002, reason="Unknown agent")
            return
            
        if agent.status == "revoked":
            logger.warning("Revoked agent attempted connection", agent_id=agent.agent_id)
            await websocket.close(code=4003, reason="Certificate revoked")
            return
            
        agent_id = agent.agent_id
        
        # Register connection with connection manager
        connection = await connection_manager.connect(
            websocket, agent_id, cert_info["serial"], db
        )
        
        logger.info("Agent WebSocket connected", 
                   agent_id=agent_id,
                   hostname=agent.hostname,
                   connection_id=connection.connection_id)
        
        # Start background tasks if not already running
        await connection_manager.start_background_tasks()
        
        # Message handling loop
        while True:
            try:
                # Receive message from agent
                data = await websocket.receive_text()
                message = json.loads(data)
                
                # Verify message signature if present
                if "signature" in message:
                    # TODO: Implement message signature verification
                    pass
                    
                # Handle different message types
                await connection_manager.handle_agent_message(agent_id, message, db)
                
                # Send ACK for command results
                if message.get("type") == "command_result":
                    ack_message = {
                        "type": "ack",
                        "message_id": message.get("message_id"),
                        "timestamp": connection.last_heartbeat.isoformat()
                    }
                    await connection.send_message(ack_message)
                    
            except WebSocketDisconnect:
                logger.info("Agent WebSocket disconnected", agent_id=agent_id)
                break
                
            except json.JSONDecodeError as e:
                logger.warning("Invalid JSON from agent", 
                              agent_id=agent_id, error=str(e))
                error_msg = {
                    "type": "error",
                    "error": "Invalid JSON format",
                    "timestamp": connection.last_heartbeat.isoformat()
                }
                await connection.send_message(error_msg)
                
            except Exception as e:
                logger.error("Error processing agent message", 
                            agent_id=agent_id, error=str(e))
                
    except WebSocketDisconnect:
        logger.info("Agent WebSocket disconnected during handshake")
        
    except Exception as e:
        logger.error("WebSocket connection error", error=str(e))
        try:
            await websocket.close(code=4000, reason="Internal server error")
        except:
            pass
            
    finally:
        # Clean up connection
        if agent_id:
            await connection_manager.disconnect(agent_id, db)


@router.get("/ws/stats")
async def websocket_stats():
    """Get WebSocket connection statistics"""
    return connection_manager.get_connection_stats()