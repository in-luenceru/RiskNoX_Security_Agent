"""
Modern RiskNoX Agent - WebSocket Client with Manager Integration
"""

import asyncio
import json
import uuid
import ssl
import platform
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, Callable
import logging

import websockets
from websockets.exceptions import ConnectionClosed, InvalidURI
import structlog

from enrollment import AgentEnrollment
from command_handler import CommandHandler
from certificate_manager import CertificateManager

# Configure logging
logging.basicConfig(level=logging.INFO)
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


class AgentWebSocketClient:
    """
    Modern agent client with mTLS WebSocket communication to Manager
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.manager_url = config.get("manager_url", "wss://localhost:8000")
        self.agent_id = config.get("agent_id")
        self.hostname = config.get("hostname", socket.gethostname())
        
        # Try to load agent_id from agent_info.json if not in config
        if not self.agent_id:
            self.agent_id = self._load_agent_id_from_config()
        
        # Components
        self.enrollment = AgentEnrollment(self.manager_url.replace("wss://", "https://").replace("ws://", "http://"))
        self.command_handler = CommandHandler(websocket_client=self)
        self.cert_manager = CertificateManager(config.get("cert_dir", "../config"))
        
        # Connection state
        self.websocket = None
        self.is_connected = False
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 10
        self.heartbeat_interval = 30
        self.last_heartbeat = None
        
        # Message handling
        self.message_handlers: Dict[str, Callable] = {
            "welcome": self._handle_welcome,
            "command": self._handle_command,
            "heartbeat_request": self._handle_heartbeat_request,
            "disconnect": self._handle_disconnect,
            "ack": self._handle_ack,
            "error": self._handle_error
        }
        
        # Background tasks
        self._heartbeat_task = None
        self._reconnect_task = None
        
    async def start(self):
        """Start the agent client"""
        logger.info("Starting RiskNoX Agent Client", hostname=self.hostname)
        
        # Ensure we have valid certificates
        if not await self._ensure_enrollment():
            logger.error("Failed to enroll with Manager")
            return False
            
        # Start WebSocket connection
        await self._connect_with_retry()
        
        return True
        
    async def stop(self):
        """Stop the agent client"""
        logger.info("Stopping RiskNoX Agent Client")
        
        # Cancel background tasks
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        if self._reconnect_task:
            self._reconnect_task.cancel()
            
        # Close WebSocket connection
        if self.websocket and not self.websocket.closed:
            await self.websocket.close()
            
        self.is_connected = False
        
    async def _ensure_enrollment(self) -> bool:
        """Ensure agent is enrolled with valid certificate"""
        try:
            # Check if we have valid certificate
            if not self.cert_manager.has_valid_certificate():
                logger.info("No valid certificate found, enrolling with Manager")
                
                # Generate system information
                system_info = {
                    "hostname": self.hostname,
                    "os_type": platform.system(),
                    "os_version": platform.version(),
                    "agent_version": "2.0.0",
                    "ip_address": self._get_local_ip(),
                    "tags": self.config.get("tags", [])
                }
                
                # Enroll with Manager
                enrollment_result = await self.enrollment.enroll(**system_info)
                if not enrollment_result["success"]:
                    logger.error("Enrollment failed", error=enrollment_result.get("error"))
                    return False
                    
                # Save certificate and agent ID
                self.cert_manager.save_certificate(
                    enrollment_result["certificate"],
                    enrollment_result["private_key"]
                )
                
                self.agent_id = enrollment_result["agent_id"]
                
                # Update config with agent ID
                self.config["agent_id"] = self.agent_id
                
                logger.info("Enrollment successful", agent_id=self.agent_id)
                
            else:
                logger.info("Valid certificate found")
                
            return True
            
        except Exception as e:
            logger.error("Enrollment check failed", error=str(e))
            return False
            
    def _load_agent_id_from_config(self) -> Optional[str]:
        """Load agent ID from agent_info.json file"""
        try:
            # Try multiple possible locations for agent_info.json
            possible_paths = [
                Path("../config/agent_info.json"),
                Path("config/agent_info.json"),
                Path("./agent_info.json")
            ]
            
            for config_path in possible_paths:
                if config_path.exists():
                    with open(config_path, 'r') as f:
                        agent_info = json.load(f)
                        agent_id = agent_info.get("agent_id")
                        if agent_id:
                            logger.info("Loaded agent ID from config", 
                                       agent_id=agent_id, 
                                       config_file=str(config_path))
                            return agent_id
            
            logger.warning("Could not find agent_info.json with valid agent_id")
            return None
            
        except Exception as e:
            logger.error("Failed to load agent ID from config", error=str(e))
            return None
            
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Connect to a remote address to get local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"
            
    async def _connect_with_retry(self):
        """Connect to Manager with exponential backoff retry"""
        while self.reconnect_attempts < self.max_reconnect_attempts:
            try:
                await self._connect()
                if self.is_connected:
                    self.reconnect_attempts = 0
                    return
                    
            except Exception as e:
                logger.warning("Connection attempt failed", 
                              attempt=self.reconnect_attempts + 1,
                              error=str(e))
                
            self.reconnect_attempts += 1
            
            if self.reconnect_attempts < self.max_reconnect_attempts:
                # Exponential backoff: 2^attempt seconds, max 300 seconds
                delay = min(2 ** self.reconnect_attempts, 300)
                logger.info("Retrying connection", delay=delay)
                await asyncio.sleep(delay)
            else:
                logger.error("Max reconnection attempts reached")
                break
                
    async def _connect(self):
        """Establish WebSocket connection with optional mTLS"""
        try:
            # WebSocket URL
            ws_url = self.manager_url.replace("https://", "wss://").replace("http://", "ws://")
            if not ws_url.endswith("/ws/agent"):
                ws_url = ws_url.rstrip("/") + "/ws/agent"
                
            # Add certificate serial as query parameter for development
            cert_serial = self.cert_manager.get_certificate_serial()
            if cert_serial:
                ws_url += f"?cert_serial={cert_serial}"
                
            logger.info("Connecting to Manager", url=ws_url)
            
            # Only use SSL for secure WebSocket connections (wss://)
            if ws_url.startswith("wss://"):
                # Prepare SSL context for mTLS
                ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                ssl_context.check_hostname = False  # For development
                ssl_context.verify_mode = ssl.CERT_NONE  # For development
                
                # Load client certificate for mTLS
                cert_path, key_path = self.cert_manager.get_certificate_paths()
                if cert_path and key_path:
                    ssl_context.load_cert_chain(cert_path, key_path)
                
                logger.info("Using secure WebSocket connection with SSL")
                # Connect to WebSocket with SSL
                self.websocket = await websockets.connect(ws_url, ssl=ssl_context)
            else:
                logger.info("Using plain WebSocket connection (no SSL)")
                # Connect to WebSocket without SSL
                self.websocket = await websockets.connect(ws_url)
            
            self.is_connected = True
            logger.info("Connected to Manager WebSocket")
            
            # Start background tasks
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            
            # Start message handling loop
            await self._message_loop()
            
        except Exception as e:
            logger.error("WebSocket connection failed", error=str(e))
            self.is_connected = False
            if self.websocket:
                await self.websocket.close()
            raise
            
    async def _message_loop(self):
        """Main message handling loop"""
        try:
            async for message in self.websocket:
                try:
                    data = json.loads(message)
                    await self._handle_message(data)
                except json.JSONDecodeError as e:
                    logger.error("Invalid JSON received", error=str(e))
                except Exception as e:
                    logger.error("Message handling error", error=str(e))
                    
        except ConnectionClosed:
            logger.warning("WebSocket connection closed")
        except Exception as e:
            logger.error("Message loop error", error=str(e))
        finally:
            self.is_connected = False
            
    async def _handle_message(self, data: Dict[str, Any]):
        """Handle incoming message from Manager"""
        message_type = data.get("type")
        if message_type in self.message_handlers:
            await self.message_handlers[message_type](data)
        else:
            logger.warning("Unknown message type", type=message_type)
            
    async def _handle_welcome(self, data: Dict[str, Any]):
        """Handle welcome message from Manager"""
        logger.info("Received welcome from Manager", 
                   connection_id=data.get("connection_id"),
                   server_time=data.get("server_time"))
        
        self.heartbeat_interval = data.get("heartbeat_interval", 30)
        
    async def _handle_command(self, data: Dict[str, Any]):
        """Handle command from Manager"""
        command_id = data.get("command_id")
        command_type = data.get("command_type")
        payload = data.get("payload", {})
        
        # Add command_id to payload for tracking
        payload["command_id"] = command_id
        
        logger.info("Received command", 
                   command_id=command_id, 
                   command_type=command_type)
        
        try:
            # Execute command
            result = await self.command_handler.execute(command_type, payload)
            
            # Send result back to Manager
            response = {
                "type": "command_result",
                "command_id": command_id,
                "result": result,
                "timestamp": datetime.utcnow().isoformat(),
                "message_id": str(uuid.uuid4())
            }
            
            await self._send_message(response)
            
            logger.info("Command executed successfully", 
                       command_id=command_id, 
                       command_type=command_type)
            
        except Exception as e:
            logger.error("Command execution failed", 
                        command_id=command_id, 
                        error=str(e))
            
            # Send error response
            error_response = {
                "type": "command_result",
                "command_id": command_id,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
                "message_id": str(uuid.uuid4())
            }
            
            await self._send_message(error_response)
            
    async def _handle_heartbeat_request(self, data: Dict[str, Any]):
        """Handle heartbeat request from Manager"""
        response = {
            "type": "heartbeat",
            "timestamp": datetime.utcnow().isoformat(),
            "status": "alive"
        }
        await self._send_message(response)
        
    async def _handle_disconnect(self, data: Dict[str, Any]):
        """Handle disconnect message from Manager"""
        reason = data.get("reason", "unknown")
        logger.info("Manager requested disconnect", reason=reason)
        
        if self.websocket:
            await self.websocket.close()
            
    async def _handle_ack(self, data: Dict[str, Any]):
        """Handle acknowledgment from Manager"""
        message_id = data.get("message_id")
        logger.debug("Received ACK", message_id=message_id)
        
    async def _handle_error(self, data: Dict[str, Any]):
        """Handle error message from Manager"""
        error = data.get("error", "Unknown error")
        logger.error("Manager reported error", error=error)
        
    async def _send_message(self, message: Dict[str, Any]):
        """Send message to Manager"""
        if self.websocket and not self.websocket.closed:
            try:
                await self.websocket.send(json.dumps(message))
            except Exception as e:
                logger.error("Failed to send message", error=str(e))
                
    async def _heartbeat_loop(self):
        """Background heartbeat task"""
        while self.is_connected:
            try:
                self.last_heartbeat = datetime.utcnow()
                await asyncio.sleep(self.heartbeat_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Heartbeat error", error=str(e))
                break
                
    async def send_event(self, event_type: str, event_data: Dict[str, Any], 
                        severity: str = "info"):
        """Send event to Manager"""
        event_message = {
            "type": "event",
            "event_type": event_type,
            "data": event_data,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "message_id": str(uuid.uuid4())
        }
        
        await self._send_message(event_message)
        
    async def update_status(self, status_data: Dict[str, Any]):
        """Send status update to Manager"""
        status_message = {
            "type": "status_update",
            "status": status_data,
            "timestamp": datetime.utcnow().isoformat(),
            "message_id": str(uuid.uuid4())
        }
        
        await self._send_message(status_message)


async def main():
    """Main agent entry point"""
    config = {
        "manager_url": "wss://localhost:8000",
        "hostname": socket.gethostname(),
        "tags": ["windows", "workstation"],
        "cert_dir": "./certs"
    }
    
    agent = AgentWebSocketClient(config)
    
    try:
        await agent.start()
        
        # Keep running until interrupted
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Agent interrupted by user")
    except Exception as e:
        logger.error("Agent crashed", error=str(e))
    finally:
        await agent.stop()


if __name__ == "__main__":
    asyncio.run(main())