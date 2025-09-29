"""
Manager Bridge - Command Translator
Translates admin UI actions to exact agent command payloads matching the local UI behavior
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import uuid
import logging

logger = logging.getLogger(__name__)


class CommandTranslator:
    """Translates admin actions to agent commands with exact UI-equivalent payloads"""
    
    def __init__(self):
        self.supported_actions = {
            'run_scan': self.translate_run_scan,
            'cancel_scan': self.translate_cancel_scan,
            'block_url': self.translate_block_url,
            'unblock_url': self.translate_unblock_url,
            'get_blocked_urls': self.translate_get_blocked_urls,
            'install_patches': self.translate_install_patches,
            'check_patches': self.translate_check_patches,
            'get_patch_info': self.translate_get_patch_info,
            'get_system_info': self.translate_get_system_info,
            'restart_agent': self.translate_restart_agent,
            'update_config': self.translate_update_config,
            'cleanup_agent': self.translate_cleanup_agent
        }
    
    def translate_action(self, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate an admin action to agent command format
        
        Args:
            action: Action type (e.g., 'run_scan', 'block_url')
            payload: Action-specific payload
            
        Returns:
            Agent command in format expected by command_handler.py
        """
        if action not in self.supported_actions:
            raise ValueError(f"Unsupported action: {action}")
            
        logger.info(f"Translating action: {action}", extra={"action": action, "payload": payload})
        
        return self.supported_actions[action](payload)
    
    def translate_run_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate scan request to agent scan command
        Matches exact format from web/app.js startScan(), startQuickScan()
        """
        scan_type = payload.get('scan_type', 'quick_system')
        custom_path = payload.get('path')
        options = payload.get('options', {})
        
        # Map UI scan types to agent command format
        if scan_type == 'quick_system' or scan_type == 'quick':
            command_payload = {
                "scan_type": "quick",
                "targets": [],  # Quick scan doesn't need specific targets
                "options": {
                    "heuristics": options.get("heuristics", True),
                    "real_time": options.get("real_time", True),
                    "max_file_size": "50MB",
                    "timeout": 1800  # 30 minutes for quick scan
                }
            }
        elif scan_type == 'system' or scan_type == 'full':
            command_payload = {
                "scan_type": "full",
                "targets": [],  # Full scan uses system default
                "options": {
                    "recursive": options.get("recursive", True),
                    "follow_symlinks": options.get("follow_symlinks", False),
                    "heuristics": options.get("heuristics", True),
                    "timeout": 7200  # 2 hours for full scan
                }
            }
        elif scan_type == 'directory' or scan_type == 'custom':
            if not custom_path:
                raise ValueError("Directory scan requires 'path' parameter")
            command_payload = {
                "scan_type": "custom",
                "targets": [custom_path] if isinstance(custom_path, str) else custom_path,
                "options": {
                    "recursive": options.get("recursive", True),
                    "follow_symlinks": options.get("follow_symlinks", False),
                    "heuristics": options.get("heuristics", True),
                    "timeout": options.get("timeout", 3600)  # 1 hour default
                }
            }
        else:
            raise ValueError(f"Unsupported scan type: {scan_type}")
            
        return {
            "command_type": "scan",
            "payload": command_payload
        }
    
    def translate_cancel_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate scan cancellation request
        Matches format from web/app.js cancelCurrentScan()
        """
        session_id = payload.get('session_id')
        if not session_id:
            raise ValueError("Cancel scan requires 'session_id' parameter")
            
        return {
            "command_type": "cancel_scan",
            "payload": {
                "session_id": session_id,
                "force": payload.get("force", False)
            }
        }
    
    def translate_block_url(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate URL blocking request
        Matches format from web/app.js blockUrl() and React UI runWebBlockCommand()
        """
        url = payload.get('url')
        urls = payload.get('urls', [])
        
        # Handle both single URL and multiple URLs
        if url and not urls:
            urls = [url]
        elif not urls:
            raise ValueError("Block URL requires 'url' or 'urls' parameter")
            
        # Clean URLs (remove protocol, paths for hosts file blocking)
        cleaned_urls = []
        for url in urls:
            if url:
                # Remove protocols and paths for hosts file entries
                clean_url = url.replace("http://", "").replace("https://", "").split("/")[0]
                if clean_url and clean_url not in cleaned_urls:
                    cleaned_urls.append(clean_url)
                    
        if not cleaned_urls:
            raise ValueError("No valid URLs provided for blocking")
            
        return {
            "command_type": "web_block",
            "payload": {
                "urls": cleaned_urls,
                "method": payload.get("method", "hosts_file"),  # hosts_file, dns, firewall
                "category": payload.get("category", "admin_blocked")
            }
        }
    
    def translate_unblock_url(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate URL unblocking request
        Matches format from web/app.js unblockUrl() and React UI runWebBlockCommand()
        """
        url = payload.get('url')
        urls = payload.get('urls', [])
        
        # Handle both single URL and multiple URLs
        if url and not urls:
            urls = [url]
        elif not urls:
            raise ValueError("Unblock URL requires 'url' or 'urls' parameter")
            
        # Clean URLs to match hosts file format
        cleaned_urls = []
        for url in urls:
            if url:
                clean_url = url.replace("http://", "").replace("https://", "").split("/")[0]
                if clean_url and clean_url not in cleaned_urls:
                    cleaned_urls.append(clean_url)
                    
        if not cleaned_urls:
            raise ValueError("No valid URLs provided for unblocking")
            
        return {
            "command_type": "web_unblock",
            "payload": {
                "urls": cleaned_urls,
                "method": payload.get("method", "hosts_file")
            }
        }
    
    def translate_get_blocked_urls(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate blocked URLs list request
        Matches format from web/app.js loadBlockedUrls()
        """
        return {
            "command_type": "web_list_blocked",
            "payload": {
                "include_metadata": payload.get("include_metadata", True),
                "format": payload.get("format", "list")  # list, detailed
            }
        }
    
    def translate_install_patches(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate patch installation request
        Matches format from web/app.js installUpdates() and React UI runPatchCommand()
        """
        patch_ids = payload.get('patch_ids', [])
        install_all = payload.get('install_all', len(patch_ids) == 0)
        
        return {
            "command_type": "patch",
            "payload": {
                "patch_ids": patch_ids,
                "install_options": {
                    "auto_reboot": payload.get("auto_reboot", False),
                    "backup_before_install": payload.get("backup_before_install", True),
                    "rollback_on_failure": payload.get("rollback_on_failure", True),
                    "install_all_pending": install_all,
                    "exclude_optional": payload.get("exclude_optional", True),
                    "timeout": payload.get("timeout", 3600)  # 1 hour default
                }
            }
        }
    
    def translate_check_patches(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate patch check request
        Matches format from web/app.js checkForUpdates()
        """
        return {
            "command_type": "patch_check",
            "payload": {
                "include_optional": payload.get("include_optional", False),
                "include_drivers": payload.get("include_drivers", True),
                "include_preview": payload.get("include_preview", False),
                "force_check": payload.get("force_check", True)
            }
        }
    
    def translate_get_patch_info(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate patch info request
        Matches format from web/app.js loadPatchInfo()
        """
        return {
            "command_type": "patch_info",
            "payload": {
                "include_installed": payload.get("include_installed", True),
                "include_pending": payload.get("include_pending", True),
                "include_history": payload.get("include_history", True),
                "include_system_info": payload.get("include_system_info", True)
            }
        }
    
    def translate_get_system_info(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate system info request
        Matches format from web/app.js loadSystemStatus()
        """
        return {
            "command_type": "system_info",
            "payload": {
                "include_network": payload.get("include_network", True),
                "include_processes": payload.get("include_processes", False),
                "include_services": payload.get("include_services", False),
                "include_disk": payload.get("include_disk", True),
                "include_memory": payload.get("include_memory", True),
                "include_cpu": payload.get("include_cpu", True)
            }
        }
    
    def translate_restart_agent(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate agent restart request
        """
        return {
            "command_type": "restart_agent",
            "payload": {
                "graceful": payload.get("graceful", True),
                "delay_seconds": payload.get("delay_seconds", 5),
                "reason": payload.get("reason", "Manager requested restart")
            }
        }
    
    def translate_update_config(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate configuration update request
        """
        config_updates = payload.get('config', {})
        if not config_updates:
            raise ValueError("Configuration update requires 'config' parameter")
            
        return {
            "command_type": "config",
            "payload": {
                "config": config_updates,
                "restart_required": payload.get("restart_required", False),
                "backup_current": payload.get("backup_current", True)
            }
        }
    
    def translate_cleanup_agent(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate agent cleanup request
        """
        return {
            "command_type": "cleanup",
            "payload": {
                "clear_logs": payload.get("clear_logs", False),
                "clear_cache": payload.get("clear_cache", True),
                "clear_temp": payload.get("clear_temp", True),
                "optimize_db": payload.get("optimize_db", False)
            }
        }
    
    def get_supported_actions(self) -> List[str]:
        """Return list of supported action types"""
        return list(self.supported_actions.keys())
    
    def validate_action_payload(self, action: str, payload: Dict[str, Any]) -> bool:
        """
        Validate that an action payload has required fields
        
        Args:
            action: Action type
            payload: Action payload
            
        Returns:
            True if valid, raises ValueError if invalid
        """
        if action not in self.supported_actions:
            raise ValueError(f"Unsupported action: {action}")
        
        # Action-specific validation
        if action == 'run_scan':
            scan_type = payload.get('scan_type', 'quick_system')
            if scan_type in ['directory', 'custom'] and not payload.get('path'):
                raise ValueError("Directory scan requires 'path' parameter")
        
        elif action == 'cancel_scan':
            if not payload.get('session_id'):
                raise ValueError("Cancel scan requires 'session_id' parameter")
        
        elif action in ['block_url', 'unblock_url']:
            if not payload.get('url') and not payload.get('urls'):
                raise ValueError(f"{action} requires 'url' or 'urls' parameter")
        
        elif action == 'update_config':
            if not payload.get('config'):
                raise ValueError("Configuration update requires 'config' parameter")
        
        return True


def create_command_translator() -> CommandTranslator:
    """Factory function to create a command translator instance"""
    return CommandTranslator()


# Example usage for testing
if __name__ == "__main__":
    translator = create_command_translator()
    
    # Test scan translation
    scan_command = translator.translate_action('run_scan', {
        'scan_type': 'quick_system',
        'options': {'heuristics': True}
    })
    print("Quick scan command:", scan_command)
    
    # Test web blocking translation
    block_command = translator.translate_action('block_url', {
        'url': 'https://malicious-site.com'
    })
    print("Block URL command:", block_command)
    
    # Test patch installation translation
    patch_command = translator.translate_action('install_patches', {
        'patch_ids': ['KB5028166'],
        'auto_reboot': False
    })
    print("Patch install command:", patch_command)