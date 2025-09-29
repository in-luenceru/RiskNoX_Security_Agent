"""
Agent Emulator for Integration Testing
Simulates an agent connecting to Manager and responding to commands
"""

import asyncio
import json
import websockets
import ssl
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import uuid

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AgentEmulator:
    """
    Emulates a RiskNoX agent for testing Manager Bridge functionality
    Connects via WebSocket and responds to Manager commands
    """
    
    def __init__(self, agent_id: str, manager_host: str = "localhost", 
                 manager_port: int = 8444, use_ssl: bool = False):
        self.agent_id = agent_id
        self.manager_host = manager_host
        self.manager_port = manager_port
        self.use_ssl = use_ssl
        self.websocket = None
        self.running = False
        self.received_commands = []
        self.command_responses = {}
        
        # Simulated agent state
        self.scan_sessions = {}
        self.blocked_urls = []
        self.system_info = {
            "hostname": f"test-agent-{agent_id}",
            "os": {"system": "Windows", "version": "10.0.19044"},
            "cpu": {"count": 4, "usage_percent": 25.5},
            "memory": {"total": 8589934592, "percent": 45.2},
            "disk": [{"device": "C:", "percent": 60.0}]
        }
    
    async def connect(self):
        """Connect to Manager WebSocket"""
        uri = f"{'wss' if self.use_ssl else 'ws'}://{self.manager_host}:{self.manager_port}/ws/agent"
        
        ssl_context = None
        if self.use_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        try:
            self.websocket = await websockets.connect(
                uri, 
                ssl=ssl_context,
                extra_headers={
                    "X-Agent-ID": self.agent_id,
                    "X-Agent-Version": "2.0.0"
                }
            )
            self.running = True
            logger.info(f"Agent {self.agent_id} connected to Manager")
            
            # Start message handling
            await asyncio.gather(
                self._message_handler(),
                self._heartbeat_sender()
            )
            
        except Exception as e:
            logger.error(f"Failed to connect agent {self.agent_id}: {e}")
            raise
    
    async def disconnect(self):
        """Disconnect from Manager"""
        self.running = False
        if self.websocket:
            await self.websocket.close()
        logger.info(f"Agent {self.agent_id} disconnected")
    
    async def _message_handler(self):
        """Handle incoming messages from Manager"""
        try:
            async for message in self.websocket:
                try:
                    data = json.loads(message)
                    await self._process_message(data)
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON received: {e}")
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Agent {self.agent_id} connection closed")
        except Exception as e:
            logger.error(f"Message handler error: {e}")
        finally:
            self.running = False
    
    async def _heartbeat_sender(self):
        """Send periodic heartbeats to Manager"""
        while self.running:
            try:
                heartbeat = {
                    "type": "heartbeat",
                    "agent_id": self.agent_id,
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                await self._send_message(heartbeat)
                await asyncio.sleep(30)  # Heartbeat every 30 seconds
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                break
    
    async def _send_message(self, message: Dict[str, Any]):
        """Send message to Manager"""
        if self.websocket and self.running:
            await self.websocket.send(json.dumps(message))
    
    async def _process_message(self, message: Dict[str, Any]):
        """Process incoming message from Manager"""
        message_type = message.get("type")
        
        logger.info(f"Agent {self.agent_id} received message: {message_type}")
        
        if message_type == "welcome":
            await self._handle_welcome(message)
        elif message_type == "command":
            await self._handle_command(message)
        elif message_type == "disconnect":
            await self._handle_disconnect(message)
        else:
            logger.warning(f"Unknown message type: {message_type}")
    
    async def _handle_welcome(self, message: Dict[str, Any]):
        """Handle welcome message from Manager"""
        logger.info(f"Agent {self.agent_id} received welcome message")
    
    async def _handle_command(self, message: Dict[str, Any]):
        """Handle command from Manager Bridge"""
        command = message.get("command", {})
        command_id = command.get("command_id")
        command_type = command.get("command_type")
        payload = command.get("payload", {})
        
        logger.info(f"Agent {self.agent_id} received command: {command_type} ({command_id})")
        
        # Store received command for verification
        self.received_commands.append(command)
        
        # Send immediate ACK
        ack_message = {
            "type": "command_ack",
            "command_id": command_id,
            "agent_id": self.agent_id,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        await self._send_message(ack_message)
        
        # Process command and send result
        try:
            result = await self._execute_command(command_type, payload)
            
            result_message = {
                "type": "command_result",
                "command_id": command_id,
                "agent_id": self.agent_id,
                "result": result,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            await self._send_message(result_message)
            
            # Store response for verification
            self.command_responses[command_id] = result
            
        except Exception as e:
            error_message = {
                "type": "command_result",
                "command_id": command_id,
                "agent_id": self.agent_id,
                "result": {
                    "success": False,
                    "error": str(e)
                },
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            await self._send_message(error_message)
    
    async def _handle_disconnect(self, message: Dict[str, Any]):
        """Handle disconnect message from Manager"""
        logger.info(f"Agent {self.agent_id} received disconnect message")
        await self.disconnect()
    
    async def _execute_command(self, command_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute command and return result
        Simulates the same responses as real agent command_handler.py
        """
        if command_type == "scan":
            return await self._simulate_scan(payload)
        elif command_type == "web_block":
            return await self._simulate_web_block(payload)
        elif command_type == "web_unblock":
            return await self._simulate_web_unblock(payload)
        elif command_type == "web_list_blocked":
            return await self._simulate_web_list(payload)
        elif command_type == "patch":
            return await self._simulate_patch(payload)
        elif command_type == "system_info":
            return await self._simulate_system_info(payload)
        elif command_type == "config":
            return await self._simulate_config(payload)
        elif command_type == "cleanup":
            return await self._simulate_cleanup(payload)
        else:
            return {
                "success": False,
                "error": f"Unknown command type: {command_type}"
            }
    
    async def _simulate_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate antivirus scan execution"""
        scan_type = payload.get("scan_type", "quick")
        targets = payload.get("targets", [])
        
        # Simulate scan execution time
        await asyncio.sleep(2)
        
        # Simulate scan results
        if scan_type == "quick":
            files_scanned = 150
            threats_found = 0
        elif scan_type == "full":
            files_scanned = 25000
            threats_found = 1  # Simulate finding one threat
        else:
            files_scanned = 500
            threats_found = 0
        
        session_id = str(uuid.uuid4())
        self.scan_sessions[session_id] = {
            "scan_type": scan_type,
            "files_scanned": files_scanned,
            "threats_found": threats_found,
            "completed_at": datetime.utcnow().isoformat()
        }
        
        return {
            "success": True,
            "scan_type": scan_type,
            "files_scanned": files_scanned,
            "threats_found": threats_found,
            "session_id": session_id,
            "scan_completed_at": datetime.utcnow().isoformat() + "Z",
            "execution_logs": [
                "Scan started successfully",
                f"Scanned {files_scanned} files",
                f"Found {threats_found} threats" if threats_found > 0 else "No threats detected"
            ]
        }
    
    async def _simulate_web_block(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate web URL blocking"""
        urls = payload.get("urls", [])
        
        blocked_count = 0
        for url in urls:
            if url not in self.blocked_urls:
                self.blocked_urls.append(url)
                blocked_count += 1
        
        return {
            "success": True,
            "urls_blocked": blocked_count,
            "total_urls": len(urls),
            "blocked_at": datetime.utcnow().isoformat() + "Z"
        }
    
    async def _simulate_web_unblock(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate web URL unblocking"""
        urls = payload.get("urls", [])
        
        unblocked_count = 0
        for url in urls:
            if url in self.blocked_urls:
                self.blocked_urls.remove(url)
                unblocked_count += 1
        
        return {
            "success": True,
            "urls_unblocked": unblocked_count,
            "total_urls": len(urls),
            "unblocked_at": datetime.utcnow().isoformat() + "Z"
        }
    
    async def _simulate_web_list(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate listing blocked URLs"""
        return {
            "success": True,
            "blocked_urls": [
                {
                    "url": url,
                    "blocked_at": datetime.utcnow().isoformat() + "Z",
                    "method": "hosts_file"
                }
                for url in self.blocked_urls
            ],
            "total_count": len(self.blocked_urls)
        }
    
    async def _simulate_patch(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate patch installation"""
        patch_ids = payload.get("patch_ids", [])
        
        # Simulate patch installation time
        await asyncio.sleep(3)
        
        return {
            "success": True,
            "patches_installed": len(patch_ids) if patch_ids else 3,
            "reboot_required": False,
            "installation_completed_at": datetime.utcnow().isoformat() + "Z"
        }
    
    async def _simulate_system_info(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate system information collection"""
        return {
            "success": True,
            "system_info": self.system_info
        }
    
    async def _simulate_config(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate configuration update"""
        config_updates = payload.get("config", {})
        
        return {
            "success": True,
            "config_updated": len(config_updates),
            "updated_at": datetime.utcnow().isoformat() + "Z"
        }
    
    async def _simulate_cleanup(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate agent cleanup"""
        return {
            "success": True,
            "cleaned_items": 5,
            "items": ["temp_files", "old_logs", "cache"],
            "cleaned_at": datetime.utcnow().isoformat() + "Z"
        }
    
    def get_received_commands(self) -> list:
        """Get list of commands received from Manager"""
        return self.received_commands.copy()
    
    def get_command_response(self, command_id: str) -> Optional[Dict[str, Any]]:
        """Get response for specific command"""
        return self.command_responses.get(command_id)
    
    def clear_history(self):
        """Clear command history for new tests"""
        self.received_commands.clear()
        self.command_responses.clear()


# Example usage
if __name__ == "__main__":
    async def test_agent_emulator():
        agent = AgentEmulator("test-agent-123")
        
        try:
            await agent.connect()
        except KeyboardInterrupt:
            logger.info("Shutting down agent emulator")
        finally:
            await agent.disconnect()
    
    asyncio.run(test_agent_emulator())