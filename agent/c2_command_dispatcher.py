"""
Agent C2 Command Dispatcher
Receives Manager commands via WebSocket and routes them to existing UI handler functions
"""

import json
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import base64
import structlog
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# Import existing command handler
from command_handler import CommandHandler

logger = structlog.get_logger()


class C2CommandDispatcher:
    """
    Dispatcher that receives Manager commands and routes them to existing agent handlers
    Ensures Manager-triggered commands use identical code paths as UI-triggered operations
    """
    
    def __init__(self, manager_public_key_path: Optional[str] = None):
        """
        Initialize C2 command dispatcher
        
        Args:
            manager_public_key_path: Path to Manager's public key for signature verification
        """
        self.command_handler = CommandHandler()
        self.manager_public_key = self._load_manager_public_key(manager_public_key_path)
        self.processed_commands = set()  # Prevent replay attacks
        
        # Map Manager command types to local handler methods
        self.command_routing = {
            "scan": self._handle_scan_command,
            "cancel_scan": self._handle_cancel_scan_command,
            "web_block": self._handle_web_block_command,
            "web_unblock": self._handle_web_unblock_command,
            "web_list_blocked": self._handle_web_list_command,
            "patch": self._handle_patch_command,
            "patch_check": self._handle_patch_check_command,
            "patch_info": self._handle_patch_info_command,
            "system_info": self._handle_system_info_command,
            "config": self._handle_config_command,
            "restart_agent": self._handle_restart_command,
            "cleanup": self._handle_cleanup_command
        }
        
    def _load_manager_public_key(self, key_path: Optional[str]):
        """Load Manager's public key for signature verification"""
        if key_path and Path(key_path).exists():
            try:
                with open(key_path, 'rb') as key_file:
                    public_key = serialization.load_pem_public_key(key_file.read())
                logger.info("Loaded Manager public key for command verification", key_path=key_path)
                return public_key
            except Exception as e:
                logger.warning("Failed to load Manager public key", error=str(e))
        
        logger.warning("No Manager public key available - signature verification disabled")
        return None
    
    def _verify_command_signature(self, command: Dict[str, Any]) -> bool:
        """
        Verify command signature to ensure it came from authorized Manager
        
        Args:
            command: Signed command from Manager
            
        Returns:
            True if signature is valid or verification is disabled
        """
        if not self.manager_public_key:
            logger.warning("Signature verification disabled - no Manager public key")
            return True
            
        try:
            signature = command.get("signature")
            if not signature:
                logger.error("Command missing signature")
                return False
            
            # Create command data without signature for verification
            command_data = {k: v for k, v in command.items() if k != "signature"}
            canonical_json = json.dumps(command_data, sort_keys=True, separators=(',', ':'))
            message_bytes = canonical_json.encode('utf-8')
            
            # Verify signature
            signature_bytes = base64.b64decode(signature)
            self.manager_public_key.verify(
                signature_bytes,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            logger.info("Command signature verified", command_id=command.get("command_id"))
            return True
            
        except InvalidSignature:
            logger.error("Invalid command signature", command_id=command.get("command_id"))
            return False
        except Exception as e:
            logger.error("Signature verification failed", error=str(e))
            return False
    
    def _validate_command_freshness(self, command: Dict[str, Any]) -> bool:
        """
        Validate command hasn't expired and prevent replay attacks
        
        Args:
            command: Command to validate
            
        Returns:
            True if command is fresh and valid
        """
        command_id = command.get("command_id")
        
        # Check for replay attack
        if command_id in self.processed_commands:
            logger.error("Replay attack detected", command_id=command_id)
            return False
        
        # Check expiration
        expires_at_str = command.get("expires_at")
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(expires_at_str.replace("Z", ""))
                if datetime.utcnow() > expires_at:
                    logger.error("Command expired", command_id=command_id, expires_at=expires_at_str)
                    return False
            except Exception as e:
                logger.error("Invalid expires_at format", expires_at=expires_at_str, error=str(e))
                return False
        
        # Mark as processed
        self.processed_commands.add(command_id)
        
        # Keep processed commands list from growing too large
        if len(self.processed_commands) > 10000:
            # Remove oldest 1000 entries (simple FIFO)
            old_commands = list(self.processed_commands)[:1000]
            self.processed_commands -= set(old_commands)
        
        return True
    
    async def handle_c2_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for handling Manager commands
        Validates, routes, and executes commands using existing agent code paths
        
        Args:
            command: Signed command from Manager
            
        Returns:
            Command execution result
        """
        command_id = command.get("command_id", "unknown")
        command_type = command.get("command_type")
        
        logger.info("Received C2 command", command_id=command_id, command_type=command_type)
        
        try:
            # Security validation
            if not self._verify_command_signature(command):
                return {
                    "success": False,
                    "error": "Invalid command signature",
                    "command_id": command_id
                }
            
            if not self._validate_command_freshness(command):
                return {
                    "success": False,
                    "error": "Command expired or replayed",
                    "command_id": command_id
                }
            
            # Route to appropriate handler
            if command_type not in self.command_routing:
                return {
                    "success": False,
                    "error": f"Unknown command type: {command_type}",
                    "command_id": command_id
                }
            
            # Execute command using existing agent handlers
            handler = self.command_routing[command_type]
            result = await handler(command)
            
            # Add metadata to result
            result["command_id"] = command_id
            result["executed_at"] = datetime.utcnow().isoformat() + "Z"
            
            logger.info("C2 command executed", 
                       command_id=command_id, 
                       command_type=command_type,
                       success=result.get("success", False))
            
            return result
            
        except Exception as e:
            logger.error("C2 command execution failed", 
                        command_id=command_id, 
                        command_type=command_type,
                        error=str(e))
            return {
                "success": False,
                "error": str(e),
                "command_id": command_id,
                "executed_at": datetime.utcnow().isoformat() + "Z"
            }
    
    # Command handlers that route to existing agent code
    
    async def _handle_scan_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle scan command by calling existing scan handler
        Routes to the EXACT same code path used by local UI
        """
        payload = command.get("payload", {})
        
        # The Manager translator ensures payload matches existing handler format
        result = await self.command_handler.execute("scan", payload)
        
        logger.info("Scan command executed via C2", 
                   command_id=command.get("command_id"),
                   scan_type=payload.get("scan_type"),
                   success=result.get("success"))
        
        return result
    
    async def _handle_cancel_scan_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Handle scan cancellation - would need to implement in command_handler"""
        payload = command.get("payload", {})
        session_id = payload.get("session_id")
        
        # This would need to be implemented in command_handler.py
        # For now, return a placeholder response
        return {
            "success": True,
            "message": f"Scan cancellation requested for session {session_id}",
            "session_id": session_id
        }
    
    async def _handle_web_block_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle web blocking by calling existing web_block handler
        Routes to the EXACT same code path used by local UI
        """
        payload = command.get("payload", {})
        
        # The Manager translator ensures payload matches existing handler format
        result = await self.command_handler.execute("web_block", payload)
        
        logger.info("Web block command executed via C2",
                   command_id=command.get("command_id"),
                   urls=payload.get("urls"),
                   success=result.get("success"))
        
        return result
    
    async def _handle_web_unblock_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle web unblocking by calling existing web_unblock handler
        Routes to the EXACT same code path used by local UI
        """
        payload = command.get("payload", {})
        
        # The Manager translator ensures payload matches existing handler format
        result = await self.command_handler.execute("web_unblock", payload)
        
        logger.info("Web unblock command executed via C2",
                   command_id=command.get("command_id"),
                   urls=payload.get("urls"),
                   success=result.get("success"))
        
        return result
    
    async def _handle_web_list_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Handle web blocking list request by reading hosts file"""
        try:
            # Use existing logic to read blocked URLs
            # This would call the same function as the local UI /api/web-blocking/urls endpoint
            
            import platform
            if platform.system() == "Windows":
                hosts_file = "C:\\Windows\\System32\\drivers\\etc\\hosts"
            else:
                hosts_file = "/etc/hosts"
            
            blocked_urls = []
            try:
                with open(hosts_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("127.0.0.1") and "RiskNoX" in line:
                            # Extract URL from hosts file entry
                            parts = line.split()
                            if len(parts) >= 2:
                                url = parts[1]
                                blocked_urls.append({
                                    "url": url,
                                    "blocked_at": datetime.utcnow().isoformat() + "Z",
                                    "method": "hosts_file"
                                })
            except Exception as e:
                logger.error("Failed to read hosts file", error=str(e))
            
            return {
                "success": True,
                "blocked_urls": blocked_urls,
                "total_count": len(blocked_urls)
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _handle_patch_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle patch installation by calling existing patch handler
        Routes to the EXACT same code path used by local UI
        """
        payload = command.get("payload", {})
        
        # The Manager translator ensures payload matches existing handler format
        result = await self.command_handler.execute("patch", payload)
        
        logger.info("Patch command executed via C2",
                   command_id=command.get("command_id"),
                   patch_ids=payload.get("patch_ids"),
                   success=result.get("success"))
        
        return result
    
    async def _handle_patch_check_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Handle patch check request - check for available updates"""
        try:
            # This would implement the same logic as /api/patch-management/updates/check
            # For now, return a placeholder response
            return {
                "success": True,
                "pending_updates": [],
                "update_count": 0,
                "last_check": datetime.utcnow().isoformat() + "Z"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _handle_patch_info_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Handle patch info request - get system patch status"""
        try:
            # This would implement the same logic as /api/patch-management/info
            # For now, return a placeholder response
            return {
                "success": True,
                "system_info": {
                    "os_name": "Windows 10",
                    "os_version": "10.0.19044",
                    "last_check": datetime.utcnow().isoformat() + "Z"
                },
                "installed_patches": [],
                "pending_updates": [],
                "update_history": []
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _handle_system_info_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle system info request by calling existing system_info handler
        Routes to the EXACT same code path used by local UI
        """
        payload = command.get("payload", {})
        
        # The Manager translator ensures payload matches existing handler format
        result = await self.command_handler.execute("system_info", payload)
        
        logger.info("System info command executed via C2",
                   command_id=command.get("command_id"),
                   success=result.get("success"))
        
        return result
    
    async def _handle_config_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle configuration update by calling existing config handler
        Routes to the EXACT same code path used by local UI
        """
        payload = command.get("payload", {})
        
        # The Manager translator ensures payload matches existing handler format
        result = await self.command_handler.execute("config", payload)
        
        logger.info("Config command executed via C2",
                   command_id=command.get("command_id"),
                   success=result.get("success"))
        
        return result
    
    async def _handle_restart_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle agent restart by calling existing restart handler
        Routes to the EXACT same code path used by local UI
        """
        payload = command.get("payload", {})
        
        # The Manager translator ensures payload matches existing handler format
        result = await self.command_handler.execute("restart_agent", payload)
        
        logger.info("Restart command executed via C2",
                   command_id=command.get("command_id"),
                   success=result.get("success"))
        
        return result
    
    async def _handle_cleanup_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle cleanup by calling existing cleanup handler
        Routes to the EXACT same code path used by local UI
        """
        payload = command.get("payload", {})
        
        # The Manager translator ensures payload matches existing handler format
        result = await self.command_handler.execute("cleanup", payload)
        
        logger.info("Cleanup command executed via C2",
                   command_id=command.get("command_id"),
                   success=result.get("success"))
        
        return result


def create_c2_dispatcher(manager_public_key_path: Optional[str] = None) -> C2CommandDispatcher:
    """Factory function to create a C2 command dispatcher"""
    return C2CommandDispatcher(manager_public_key_path)


# Example usage for testing
if __name__ == "__main__":
    async def test_c2_dispatcher():
        dispatcher = create_c2_dispatcher()
        
        # Test command handling
        test_command = {
            "command_id": "test-123",
            "command_type": "system_info",
            "payload": {
                "include_network": True,
                "include_disk": True
            },
            "issued_by": "admin@test.com",
            "issued_at": datetime.utcnow().isoformat() + "Z",
            "expires_at": (datetime.utcnow().replace(microsecond=0) + 
                          timedelta(minutes=5)).isoformat() + "Z"
        }
        
        result = await dispatcher.handle_c2_command(test_command)
        print("Test command result:", json.dumps(result, indent=2))
    
    import sys
    sys.path.append('..')
    from datetime import timedelta
    asyncio.run(test_c2_dispatcher())