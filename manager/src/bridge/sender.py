"""
Manager Bridge - Command Sender
Securely signs and delivers commands to agents via WebSocket C2 channel
"""

import uuid
import json
import asyncio
import base64
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import logging

logger = logging.getLogger(__name__)


class CommandSender:
    """Signs and sends commands to agents via secure WebSocket channel"""
    
    def __init__(self, private_key_path: Optional[str] = None, connection_manager=None, database=None):
        """
        Initialize command sender
        
        Args:
            private_key_path: Path to Manager private key for signing commands
            connection_manager: WebSocket connection manager instance
            database: Database instance for command tracking
        """
        self.private_key = self._load_private_key(private_key_path)
        self.connection_manager = connection_manager
        self.database = database
        self.pending_commands = {}  # In-memory tracking for fast access
        self.default_ttl_seconds = 300  # 5 minutes
        self.max_retries = 3
        self.retry_delay_seconds = 30
        
    def _load_private_key(self, key_path: Optional[str]):
        """Load Manager private key for command signing"""
        if key_path:
            try:
                with open(key_path, 'rb') as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None  # In production, use encrypted keys
                    )
                logger.info("Loaded private key for command signing", key_path=key_path)
                return private_key
            except Exception as e:
                logger.warning("Failed to load private key, generating temporary key", error=str(e))
        
        # Generate temporary key for development/testing
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        logger.info("Generated temporary private key for command signing")
        return private_key
    
    def _sign_command(self, command_data: Dict[str, Any]) -> str:
        """
        Digitally sign command payload
        
        Args:
            command_data: Command data to sign
            
        Returns:
            Base64-encoded signature
        """
        # Create canonical JSON representation for signing
        canonical_json = json.dumps(command_data, sort_keys=True, separators=(',', ':'))
        message_bytes = canonical_json.encode('utf-8')
        
        # Sign with RSA-PSS
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def _create_signed_command(self, agent_id: str, command_type: str, payload: Dict[str, Any], 
                              issued_by: str, priority: int = 5, ttl_seconds: Optional[int] = None) -> Dict[str, Any]:
        """
        Create a signed command ready for transmission
        
        Args:
            agent_id: Target agent UUID
            command_type: Command type (scan, patch, web_block, etc.)
            payload: Command-specific payload
            issued_by: Admin user or system identifier
            priority: Command priority (1=highest, 10=lowest)
            ttl_seconds: Time-to-live in seconds
            
        Returns:
            Signed command dict
        """
        command_id = str(uuid.uuid4())
        issued_at = datetime.utcnow()
        expires_at = issued_at + timedelta(seconds=ttl_seconds or self.default_ttl_seconds)
        
        # Core command data (what gets signed)
        command_data = {
            "command_id": command_id,
            "agent_id": agent_id,
            "command_type": command_type,
            "payload": payload,
            "issued_by": issued_by,
            "issued_at": issued_at.isoformat() + "Z",
            "expires_at": expires_at.isoformat() + "Z",
            "priority": priority
        }
        
        # Sign the command
        signature = self._sign_command(command_data)
        
        # Final command with signature
        signed_command = {
            **command_data,
            "signature": signature,
            "manager_version": "2.0.0",
            "protocol_version": "1.0"
        }
        
        logger.info("Created signed command", 
                   command_id=command_id, 
                   agent_id=agent_id, 
                   command_type=command_type)
        
        return signed_command
    
    async def send_command_to_agent(self, agent_id: str, command_type: str, payload: Dict[str, Any],
                                   issued_by: str = "manager", priority: int = 5, 
                                   ttl_seconds: Optional[int] = None) -> str:
        """
        Send command to specific agent
        
        Args:
            agent_id: Target agent UUID
            command_type: Command type from translator
            payload: Command payload from translator
            issued_by: Admin user identifier
            priority: Command priority (1=highest, 10=lowest)
            ttl_seconds: Command TTL in seconds
            
        Returns:
            Command ID for tracking
        """
        # Create signed command
        command = self._create_signed_command(
            agent_id=agent_id,
            command_type=command_type,
            payload=payload,
            issued_by=issued_by,
            priority=priority,
            ttl_seconds=ttl_seconds
        )
        
        command_id = command["command_id"]
        
        try:
            # Store command in database with status 'pending'
            if self.database:
                await self._store_command_in_db(command, status="pending")
            
            # Store in memory for quick access
            self.pending_commands[command_id] = {
                "command": command,
                "status": "pending",
                "created_at": datetime.utcnow(),
                "retry_count": 0,
                "agent_id": agent_id
            }
            
            # Attempt to send via WebSocket
            if self.connection_manager and self.connection_manager.is_agent_connected(agent_id):
                success = await self._send_via_websocket(agent_id, command)
                if success:
                    await self._update_command_status(command_id, "sent")
                    logger.info("Command sent via WebSocket", command_id=command_id, agent_id=agent_id)
                else:
                    logger.warning("Failed to send command via WebSocket", command_id=command_id, agent_id=agent_id)
                    await self._update_command_status(command_id, "failed")
            else:
                # Agent offline - command will be delivered when agent reconnects
                logger.info("Agent offline, command queued for delivery", command_id=command_id, agent_id=agent_id)
                await self._update_command_status(command_id, "queued")
            
            return command_id
            
        except Exception as e:
            logger.error("Failed to send command", command_id=command_id, agent_id=agent_id, error=str(e))
            await self._update_command_status(command_id, "error", error_message=str(e))
            raise
    
    async def _send_via_websocket(self, agent_id: str, command: Dict[str, Any]) -> bool:
        """
        Send command via WebSocket connection
        
        Args:
            agent_id: Target agent ID
            command: Signed command
            
        Returns:
            True if sent successfully
        """
        try:
            if not self.connection_manager:
                return False
                
            # Format message for WebSocket
            ws_message = {
                "type": "command",
                "command": command,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            
            # Send to agent
            success = await self.connection_manager.send_to_agent(agent_id, ws_message)
            return success
            
        except Exception as e:
            logger.error("WebSocket send failed", agent_id=agent_id, error=str(e))
            return False
    
    async def _store_command_in_db(self, command: Dict[str, Any], status: str):
        """Store command in database for persistent tracking"""
        if not self.database:
            return
            
        try:
            # Map to database Command model
            command_record = {
                "command_id": command["command_id"],
                "agent_id": command["agent_id"],
                "command_type": command["command_type"],
                "payload": command["payload"],
                "signature": command["signature"],
                "status": status,
                "priority": command["priority"],
                "created_at": datetime.fromisoformat(command["issued_at"].replace("Z", "")),
                "expires_at": datetime.fromisoformat(command["expires_at"].replace("Z", "")),
                "created_by": command["issued_by"],
                "command_metadata": {
                    "manager_version": command.get("manager_version"),
                    "protocol_version": command.get("protocol_version")
                }
            }
            
            await self.database.store_command(command_record)
            
        except Exception as e:
            logger.error("Failed to store command in database", command_id=command["command_id"], error=str(e))
    
    async def _update_command_status(self, command_id: str, status: str, 
                                   error_message: Optional[str] = None, result: Optional[Dict[str, Any]] = None):
        """Update command status in database and memory"""
        # Update memory tracking
        if command_id in self.pending_commands:
            self.pending_commands[command_id]["status"] = status
            if error_message:
                self.pending_commands[command_id]["error_message"] = error_message
            if result:
                self.pending_commands[command_id]["result"] = result
        
        # Update database
        if self.database:
            try:
                await self.database.update_command_status(
                    command_id=command_id,
                    status=status,
                    error_message=error_message,
                    result=result
                )
            except Exception as e:
                logger.error("Failed to update command status in database", 
                           command_id=command_id, status=status, error=str(e))
    
    async def handle_command_ack(self, command_id: str, agent_id: str):
        """Handle command acknowledgment from agent"""
        logger.info("Received command ACK", command_id=command_id, agent_id=agent_id)
        await self._update_command_status(command_id, "acknowledged")
    
    async def handle_command_result(self, command_id: str, agent_id: str, result: Dict[str, Any]):
        """Handle command result from agent"""
        success = result.get("success", False)
        status = "completed" if success else "failed"
        error_message = result.get("error") if not success else None
        
        logger.info("Received command result", 
                   command_id=command_id, 
                   agent_id=agent_id, 
                   success=success)
        
        await self._update_command_status(command_id, status, error_message=error_message, result=result)
        
        # Remove from pending commands if completed
        if command_id in self.pending_commands:
            del self.pending_commands[command_id]
    
    async def retry_failed_commands(self):
        """Retry commands that failed to send"""
        current_time = datetime.utcnow()
        
        for command_id, command_info in list(self.pending_commands.items()):
            if command_info["status"] in ["failed", "queued"] and command_info["retry_count"] < self.max_retries:
                # Check if enough time has passed for retry
                last_attempt = command_info.get("last_retry", command_info["created_at"])
                if (current_time - last_attempt).total_seconds() >= self.retry_delay_seconds:
                    
                    agent_id = command_info["agent_id"]
                    command = command_info["command"]
                    
                    logger.info("Retrying command", command_id=command_id, agent_id=agent_id, 
                              retry_count=command_info["retry_count"] + 1)
                    
                    # Attempt retry
                    if self.connection_manager and self.connection_manager.is_agent_connected(agent_id):
                        success = await self._send_via_websocket(agent_id, command)
                        if success:
                            await self._update_command_status(command_id, "sent")
                        else:
                            command_info["retry_count"] += 1
                            command_info["last_retry"] = current_time
                    else:
                        # Agent still offline
                        command_info["last_retry"] = current_time
    
    async def deliver_queued_commands(self, agent_id: str):
        """Deliver queued commands when agent comes online"""
        logger.info("Delivering queued commands for agent", agent_id=agent_id)
        
        delivered_count = 0
        for command_id, command_info in list(self.pending_commands.items()):
            if (command_info["agent_id"] == agent_id and 
                command_info["status"] in ["queued", "failed"]):
                
                command = command_info["command"]
                
                # Check if command hasn't expired
                expires_at = datetime.fromisoformat(command["expires_at"].replace("Z", ""))
                if datetime.utcnow() < expires_at:
                    success = await self._send_via_websocket(agent_id, command)
                    if success:
                        await self._update_command_status(command_id, "sent")
                        delivered_count += 1
                    else:
                        logger.warning("Failed to deliver queued command", command_id=command_id)
                else:
                    # Command expired
                    logger.info("Command expired, removing from queue", command_id=command_id)
                    await self._update_command_status(command_id, "expired")
                    del self.pending_commands[command_id]
        
        if delivered_count > 0:
            logger.info("Delivered queued commands", agent_id=agent_id, count=delivered_count)
    
    async def cleanup_expired_commands(self):
        """Remove expired commands from memory and mark as expired in DB"""
        current_time = datetime.utcnow()
        expired_commands = []
        
        for command_id, command_info in self.pending_commands.items():
            command = command_info["command"]
            expires_at = datetime.fromisoformat(command["expires_at"].replace("Z", ""))
            
            if current_time >= expires_at:
                expired_commands.append(command_id)
        
        for command_id in expired_commands:
            logger.info("Command expired", command_id=command_id)
            await self._update_command_status(command_id, "expired")
            del self.pending_commands[command_id]
    
    def get_command_status(self, command_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of a command"""
        if command_id in self.pending_commands:
            return self.pending_commands[command_id]
        return None
    
    def get_agent_command_stats(self, agent_id: str) -> Dict[str, int]:
        """Get command statistics for an agent"""
        stats = {"pending": 0, "sent": 0, "queued": 0, "failed": 0}
        
        for command_info in self.pending_commands.values():
            if command_info["agent_id"] == agent_id:
                status = command_info["status"]
                if status in stats:
                    stats[status] += 1
        
        return stats


async def create_command_sender(private_key_path: Optional[str] = None, 
                              connection_manager=None, database=None) -> CommandSender:
    """Factory function to create a command sender instance"""
    return CommandSender(private_key_path, connection_manager, database)


# Example usage for testing
if __name__ == "__main__":
    async def test_command_sender():
        sender = await create_command_sender()
        
        # Test command creation and signing
        command = sender._create_signed_command(
            agent_id="test-agent-123",
            command_type="scan",
            payload={"scan_type": "quick", "targets": []},
            issued_by="admin@test.com"
        )
        
        print("Signed command:", json.dumps(command, indent=2))
    
    # Run test
    asyncio.run(test_command_sender())