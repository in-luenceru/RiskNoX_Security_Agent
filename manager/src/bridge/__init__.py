"""
Manager Bridge - Bridge Controller
Main bridge module that combines translator and sender for the Manager UI emulator
"""

from typing import Dict, Any, Optional, List
import logging
from .translator import CommandTranslator
from .sender import CommandSender

logger = logging.getLogger(__name__)


class ManagerBridge:
    """
    Main bridge controller that translates admin actions to agent commands
    and delivers them via secure WebSocket channel
    """
    
    def __init__(self, command_sender: CommandSender):
        """
        Initialize Manager Bridge
        
        Args:
            command_sender: Configured CommandSender instance
        """
        self.translator = CommandTranslator()
        self.sender = command_sender
        
    async def execute_admin_action(self, agent_id: str, action: str, payload: Dict[str, Any],
                                 issued_by: str = "admin", priority: int = 5) -> Dict[str, Any]:
        """
        Execute an admin action by translating and sending to agent
        
        Args:
            agent_id: Target agent UUID
            action: Action type (run_scan, block_url, etc.)
            payload: Action-specific payload
            issued_by: Admin user identifier
            priority: Command priority (1=highest, 10=lowest)
            
        Returns:
            Response with command_id and status
        """
        try:
            # Validate action and payload
            self.translator.validate_action_payload(action, payload)
            
            # Translate admin action to agent command
            command = self.translator.translate_action(action, payload)
            command_type = command["command_type"]
            command_payload = command["payload"]
            
            logger.info("Executing admin action", 
                       action=action, 
                       agent_id=agent_id, 
                       command_type=command_type)
            
            # Send command to agent
            command_id = await self.sender.send_command_to_agent(
                agent_id=agent_id,
                command_type=command_type,
                payload=command_payload,
                issued_by=issued_by,
                priority=priority
            )
            
            return {
                "success": True,
                "command_id": command_id,
                "status": "dispatched",
                "message": f"Command {action} sent to agent {agent_id}"
            }
            
        except ValueError as e:
            logger.warning(f"Invalid admin action {action} for agent {agent_id}: {str(e)}")
            return {
                "success": False,
                "error": f"Invalid action: {str(e)}",
                "error_type": "validation_error"
            }
            
        except Exception as e:
            logger.error(f"Failed to execute admin action {action} for agent {agent_id}: {str(e)}")
            return {
                "success": False,
                "error": f"Execution failed: {str(e)}",
                "error_type": "execution_error"
            }
    
    async def execute_bulk_action(self, agent_ids: List[str], action: str, payload: Dict[str, Any],
                                 issued_by: str = "admin", priority: int = 5) -> Dict[str, Any]:
        """
        Execute action on multiple agents
        
        Args:
            agent_ids: List of target agent UUIDs
            action: Action type
            payload: Action-specific payload
            issued_by: Admin user identifier
            priority: Command priority
            
        Returns:
            Response with results for each agent
        """
        results = []
        successful_count = 0
        failed_count = 0
        
        for agent_id in agent_ids:
            try:
                result = await self.execute_admin_action(
                    agent_id=agent_id,
                    action=action,
                    payload=payload,
                    issued_by=issued_by,
                    priority=priority
                )
                
                results.append({
                    "agent_id": agent_id,
                    **result
                })
                
                if result["success"]:
                    successful_count += 1
                else:
                    failed_count += 1
                    
            except Exception as e:
                results.append({
                    "agent_id": agent_id,
                    "success": False,
                    "error": str(e),
                    "error_type": "execution_error"
                })
                failed_count += 1
        
        return {
            "success": failed_count == 0,
            "total_agents": len(agent_ids),
            "successful": successful_count,
            "failed": failed_count,
            "results": results
        }
    
    async def get_command_status(self, command_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific command"""
        return self.sender.get_command_status(command_id)
    
    async def get_agent_command_stats(self, agent_id: str) -> Dict[str, int]:
        """Get command statistics for an agent"""
        return self.sender.get_agent_command_stats(agent_id)
    
    def get_supported_actions(self) -> List[str]:
        """Get list of supported admin actions"""
        return self.translator.get_supported_actions()
    
    async def handle_agent_connect(self, agent_id: str):
        """Handle agent connection - deliver queued commands"""
        await self.sender.deliver_queued_commands(agent_id)
    
    async def handle_command_ack(self, command_id: str, agent_id: str):
        """Handle command acknowledgment from agent"""
        await self.sender.handle_command_ack(command_id, agent_id)
    
    async def handle_command_result(self, command_id: str, agent_id: str, result: Dict[str, Any]):
        """Handle command result from agent"""
        await self.sender.handle_command_result(command_id, agent_id, result)
    
    async def cleanup_expired_commands(self):
        """Clean up expired commands (should be called periodically)"""
        await self.sender.cleanup_expired_commands()
    
    async def retry_failed_commands(self):
        """Retry failed commands (should be called periodically)"""
        await self.sender.retry_failed_commands()


# Factory function for dependency injection
async def create_manager_bridge(connection_manager=None, database=None, 
                               private_key_path: Optional[str] = None) -> ManagerBridge:
    """
    Create a configured ManagerBridge instance
    
    Args:
        connection_manager: WebSocket connection manager
        database: Database interface
        private_key_path: Path to Manager private key
        
    Returns:
        Configured ManagerBridge instance
    """
    command_sender = CommandSender(
        private_key_path=private_key_path,
        connection_manager=connection_manager,
        database=database
    )
    
    return ManagerBridge(command_sender)


# Utility functions for common admin actions
class AdminActionHelpers:
    """Helper functions for common admin action patterns"""
    
    @staticmethod
    def create_scan_action(scan_type: str = "quick", path: Optional[str] = None, 
                          options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create a scan action payload"""
        payload = {
            "scan_type": scan_type,
            "options": options or {}
        }
        if path:
            payload["path"] = path
        return payload
    
    @staticmethod
    def create_web_block_action(urls: List[str], category: str = "admin_blocked") -> Dict[str, Any]:
        """Create a web blocking action payload"""
        return {
            "urls": urls,
            "category": category
        }
    
    @staticmethod
    def create_patch_install_action(patch_ids: Optional[List[str]] = None, 
                                   auto_reboot: bool = False) -> Dict[str, Any]:
        """Create a patch installation action payload"""
        return {
            "patch_ids": patch_ids or [],
            "auto_reboot": auto_reboot,
            "backup_before_install": True,
            "rollback_on_failure": True
        }
    
    @staticmethod
    def create_system_info_action(include_network: bool = True, 
                                 include_processes: bool = False) -> Dict[str, Any]:
        """Create a system info action payload"""
        return {
            "include_network": include_network,
            "include_processes": include_processes,
            "include_disk": True,
            "include_memory": True,
            "include_cpu": True
        }