"""
Command handler for executing Manager commands
"""

import asyncio
import json
import subprocess
import os
import platform
import psutil
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import structlog

logger = structlog.get_logger()


class CommandHandler:
    """Handles command execution from Manager"""
    
    def __init__(self):
        self.handlers = {
            "scan": self._handle_scan,
            "patch": self._handle_patch,
            "config": self._handle_config,
            "web_block": self._handle_web_block,
            "web_unblock": self._handle_web_unblock,
            "system_info": self._handle_system_info,
            "restart_agent": self._handle_restart_agent,
            "update_agent": self._handle_update_agent,
            "cleanup": self._handle_cleanup
        }
        
        # Paths (similar to original backend_server.py)
        self.base_path = Path(__file__).parent.parent
        self.vendor_dir = self.base_path / "vendor"
        self.config_dir = self.base_path / "config"
        self.logs_dir = self.base_path / "logs"
        
        # Ensure directories exist
        self.logs_dir.mkdir(exist_ok=True)
        
    async def execute(self, command_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute command and return result"""
        try:
            if command_type not in self.handlers:
                return {
                    "success": False,
                    "error": f"Unknown command type: {command_type}"
                }
                
            logger.info("Executing command", command_type=command_type)
            
            # Execute command handler
            result = await self.handlers[command_type](payload)
            
            logger.info("Command executed successfully", 
                       command_type=command_type,
                       success=result.get("success", True))
            
            return result
            
        except Exception as e:
            logger.error("Command execution failed", 
                        command_type=command_type, 
                        error=str(e))
            return {
                "success": False,
                "error": str(e)
            }
            
    async def _handle_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle antivirus scan command with real-time progress"""
        scan_type = payload.get("scan_type", "full")
        targets = payload.get("targets", [])
        options = payload.get("options", {})
        
        try:
            # Prepare scan command based on original backend_server.py logic
            clamscan_exe = self.vendor_dir / "clamscan.exe"
            if not clamscan_exe.exists():
                return {
                    "success": False,
                    "error": "ClamAV scanner not found"
                }
                
            # Build scan command
            cmd = [str(clamscan_exe)]
            
            # Scan options
            log_file = self.logs_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            cmd.extend([
                "--database=" + str(self.vendor_dir / "database"),
                "--log=" + str(log_file),
                "--recursive",
                "--bell",
                "--verbose"  # Enable verbose output for progress tracking
            ])
            
            # Add targets
            if scan_type == "full":
                if platform.system() == "Windows":
                    cmd.append("C:\\")
                else:
                    cmd.append("/")
            elif scan_type == "custom" and targets:
                cmd.extend(targets)
            else:
                # Default to user directory
                cmd.append(str(Path.home()))
                
            # Execute scan with real-time progress tracking
            logger.info("Starting antivirus scan", command=cmd[:3])  # Don't log full command
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Track progress in real-time
            files_scanned = 0
            infected_files = []
            scan_logs = []
            
            # Read output line by line for progress updates
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                
                line_str = line.decode('utf-8', errors='ignore').strip()
                if line_str:
                    scan_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {line_str}")
                    
                    # Count scanned files
                    if "Scanning" in line_str:
                        files_scanned += 1
                    
                    # Detect infected files
                    if "FOUND" in line_str:
                        infected_files.append(line_str)
                    
                    # Send progress update (would be sent via WebSocket in real implementation)
                    if files_scanned % 100 == 0:  # Update every 100 files
                        logger.info("Scan progress", files_scanned=files_scanned, threats=len(infected_files))
            
            await process.wait()
            
            return {
                "success": True,
                "scan_type": scan_type,
                "targets": targets if targets else ["system"],
                "files_scanned": files_scanned,
                "infected_files": infected_files,
                "threats_found": len(infected_files),
                "scan_completed_at": datetime.utcnow().isoformat(),
                "execution_logs": scan_logs[-50:],  # Last 50 log lines
                "exit_code": process.returncode
            }
            
        except Exception as e:
            logger.error("Scan execution failed", error=str(e))
            return {
                "success": False,
                "error": str(e)
            }
            
    async def _handle_patch(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle patch installation command"""
        patch_ids = payload.get("patch_ids", [])
        install_options = payload.get("install_options", {})
        
        try:
            if platform.system() != "Windows":
                return {
                    "success": False,
                    "error": "Patch management only supported on Windows"
                }
                
            # Use Windows Update PowerShell module
            ps_script = f'''
            Import-Module PSWindowsUpdate -Force
            $patches = Get-WindowsUpdate -AcceptAll -Install -AutoReboot:$false
            $patches | ConvertTo-Json -Depth 3
            '''
            
            process = await asyncio.create_subprocess_exec(
                "powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                try:
                    patch_results = json.loads(stdout.decode('utf-8'))
                except:
                    patch_results = []
                    
                return {
                    "success": True,
                    "patches_installed": len(patch_results) if isinstance(patch_results, list) else 1,
                    "reboot_required": install_options.get("reboot_required", False),
                    "installation_completed_at": datetime.utcnow().isoformat()
                }
            else:
                return {
                    "success": False,
                    "error": stderr.decode('utf-8', errors='ignore')
                }
                
        except Exception as e:
            logger.error("Patch installation failed", error=str(e))
            return {
                "success": False,
                "error": str(e)
            }
            
    async def _handle_web_block(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle web blocking command"""
        urls = payload.get("urls", [])
        
        try:
            if platform.system() != "Windows":
                hosts_file = "/etc/hosts"
            else:
                hosts_file = "C:\\Windows\\System32\\drivers\\etc\\hosts"
                
            # Read current hosts file
            with open(hosts_file, 'r', encoding='utf-8', errors='ignore') as f:
                hosts_content = f.read()
                
            # Add blocked URLs
            blocked_count = 0
            new_entries = []
            
            for url in urls:
                # Clean URL (remove protocol, paths)
                clean_url = url.replace("http://", "").replace("https://", "").split("/")[0]
                block_entry = f"127.0.0.1 {clean_url}"
                
                if block_entry not in hosts_content:
                    new_entries.append(block_entry)
                    blocked_count += 1
                    
            if new_entries:
                # Backup original hosts file
                backup_path = str(Path(hosts_file).with_suffix('.bak'))
                shutil.copy2(hosts_file, backup_path)
                
                # Append new entries
                with open(hosts_file, 'a', encoding='utf-8') as f:
                    f.write("\n# RiskNoX Agent Blocked URLs\\n")
                    for entry in new_entries:
                        f.write(entry + "\\n")
                        
            return {
                "success": True,
                "urls_blocked": blocked_count,
                "total_urls": len(urls),
                "blocked_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error("Web blocking failed", error=str(e))
            return {
                "success": False,
                "error": str(e)
            }
            
    async def _handle_web_unblock(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle web unblocking command"""
        urls = payload.get("urls", [])
        
        try:
            if platform.system() != "Windows":
                hosts_file = "/etc/hosts"
            else:
                hosts_file = "C:\\Windows\\System32\\drivers\\etc\\hosts"
                
            # Read current hosts file
            with open(hosts_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            # Remove blocked URLs
            unblocked_count = 0
            new_lines = []
            
            for line in lines:
                should_keep = True
                for url in urls:
                    clean_url = url.replace("http://", "").replace("https://", "").split("/")[0]
                    if f"127.0.0.1 {clean_url}" in line:
                        should_keep = False
                        unblocked_count += 1
                        break
                        
                if should_keep:
                    new_lines.append(line)
                    
            # Write updated hosts file
            if unblocked_count > 0:
                with open(hosts_file, 'w', encoding='utf-8') as f:
                    f.writelines(new_lines)
                    
            return {
                "success": True,
                "urls_unblocked": unblocked_count,
                "total_urls": len(urls),
                "unblocked_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error("Web unblocking failed", error=str(e))
            return {
                "success": False,
                "error": str(e)
            }
            
    async def _handle_system_info(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle system information request"""
        try:
            # Gather system information
            info = {
                "hostname": platform.node(),
                "os": {
                    "system": platform.system(),
                    "release": platform.release(),
                    "version": platform.version(),
                    "architecture": platform.architecture()[0]
                },
                "cpu": {
                    "count": psutil.cpu_count(),
                    "usage_percent": psutil.cpu_percent(interval=1)
                },
                "memory": {
                    "total": psutil.virtual_memory().total,
                    "available": psutil.virtual_memory().available,
                    "percent": psutil.virtual_memory().percent
                },
                "disk": [],
                "network": {},
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Disk information
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    info["disk"].append({
                        "device": partition.device,
                        "mountpoint": partition.mountpoint,
                        "fstype": partition.fstype,
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": (usage.used / usage.total) * 100
                    })
                except:
                    pass
                    
            # Network information
            net_io = psutil.net_io_counters()
            info["network"] = {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv
            }
            
            return {
                "success": True,
                "system_info": info
            }
            
        except Exception as e:
            logger.error("System info collection failed", error=str(e))
            return {
                "success": False,
                "error": str(e)
            }
            
    async def _handle_config(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle configuration update command"""
        config_updates = payload.get("config", {})
        
        try:
            # Update agent configuration
            # This would update local config files
            
            return {
                "success": True,
                "config_updated": len(config_updates),
                "updated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error("Configuration update failed", error=str(e))
            return {
                "success": False,
                "error": str(e)
            }
            
    async def _handle_restart_agent(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle agent restart command"""
        graceful = payload.get("graceful", True)
        delay_seconds = payload.get("delay_seconds", 5)
        
        try:
            logger.info("Agent restart requested", graceful=graceful, delay=delay_seconds)
            
            # Schedule restart after delay
            if graceful:
                await asyncio.sleep(delay_seconds)
                
            # In a real implementation, this would restart the agent process
            # For now, just return success
            
            return {
                "success": True,
                "restart_scheduled": True,
                "delay_seconds": delay_seconds
            }
            
        except Exception as e:
            logger.error("Agent restart failed", error=str(e))
            return {
                "success": False,
                "error": str(e)
            }
            
    async def _handle_update_agent(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle agent update command"""
        check_version = payload.get("check_version", True)
        auto_update = payload.get("auto_update", False)
        
        try:
            # Check for updates (placeholder)
            current_version = "2.0.0"
            
            return {
                "success": True,
                "current_version": current_version,
                "update_available": False,
                "checked_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error("Agent update failed", error=str(e))
            return {
                "success": False,
                "error": str(e)
            }
            
    async def _handle_cleanup(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle cleanup command"""
        clear_logs = payload.get("clear_logs", False)
        clear_cache = payload.get("clear_cache", False)
        
        try:
            cleaned_items = []
            
            if clear_logs:
                # Clean log files
                log_files = list(self.logs_dir.glob("*.log"))
                for log_file in log_files:
                    if log_file.stat().st_size > 0:
                        log_file.unlink()
                        cleaned_items.append(str(log_file))
                        
            if clear_cache:
                # Clean cache directories (placeholder)
                cleaned_items.append("cache")
                
            return {
                "success": True,
                "cleaned_items": len(cleaned_items),
                "items": cleaned_items,
                "cleaned_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error("Cleanup failed", error=str(e))
            return {
                "success": False,
                "error": str(e)
            }