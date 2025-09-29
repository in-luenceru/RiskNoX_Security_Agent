"""
Unit Tests for Manager Bridge Components
Tests translator, sender, and bridge functionality in isolation
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock
import sys
import os

# Add manager bridge to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'manager', 'src'))

from bridge.translator import CommandTranslator
from bridge.sender import CommandSender
from bridge import ManagerBridge, AdminActionHelpers


class TestCommandTranslator:
    """Unit tests for CommandTranslator"""
    
    def setup_method(self):
        self.translator = CommandTranslator()
    
    def test_translate_quick_scan(self):
        """Test quick scan translation"""
        action = "run_scan"
        payload = {
            "scan_type": "quick_system",
            "options": {"heuristics": True}
        }
        
        result = self.translator.translate_action(action, payload)
        
        assert result["command_type"] == "scan"
        assert result["payload"]["scan_type"] == "quick"
        assert result["payload"]["options"]["heuristics"] == True
        assert result["payload"]["options"]["timeout"] == 1800
    
    def test_translate_full_scan(self):
        """Test full system scan translation"""
        action = "run_scan"
        payload = {"scan_type": "system"}
        
        result = self.translator.translate_action(action, payload)
        
        assert result["command_type"] == "scan"
        assert result["payload"]["scan_type"] == "full"
        assert result["payload"]["options"]["recursive"] == True
        assert result["payload"]["options"]["timeout"] == 7200
    
    def test_translate_directory_scan(self):
        """Test directory scan translation"""
        action = "run_scan"
        payload = {
            "scan_type": "directory",
            "path": "/home/user/downloads"
        }
        
        result = self.translator.translate_action(action, payload)
        
        assert result["command_type"] == "scan"
        assert result["payload"]["scan_type"] == "custom"
        assert result["payload"]["targets"] == ["/home/user/downloads"]
    
    def test_translate_web_block(self):
        """Test web blocking translation"""
        action = "block_url"
        payload = {"url": "https://malicious-site.com/path"}
        
        result = self.translator.translate_action(action, payload)
        
        assert result["command_type"] == "web_block"
        assert result["payload"]["urls"] == ["malicious-site.com"]
        assert result["payload"]["method"] == "hosts_file"
    
    def test_translate_web_block_multiple(self):
        """Test multiple URL blocking translation"""
        action = "block_url"
        payload = {
            "urls": [
                "https://malicious-site.com",
                "http://phishing-site.org/login"
            ]
        }
        
        result = self.translator.translate_action(action, payload)
        
        assert result["command_type"] == "web_block"
        assert len(result["payload"]["urls"]) == 2
        assert "malicious-site.com" in result["payload"]["urls"]
        assert "phishing-site.org" in result["payload"]["urls"]
    
    def test_translate_patch_install(self):
        """Test patch installation translation"""
        action = "install_patches"
        payload = {
            "patch_ids": ["KB5028166", "KB5028167"],
            "auto_reboot": False
        }
        
        result = self.translator.translate_action(action, payload)
        
        assert result["command_type"] == "patch"
        assert result["payload"]["patch_ids"] == ["KB5028166", "KB5028167"]
        assert result["payload"]["install_options"]["auto_reboot"] == False
        assert result["payload"]["install_options"]["backup_before_install"] == True
    
    def test_translate_system_info(self):
        """Test system info translation"""
        action = "get_system_info"
        payload = {
            "include_network": True,
            "include_processes": False
        }
        
        result = self.translator.translate_action(action, payload)
        
        assert result["command_type"] == "system_info"
        assert result["payload"]["include_network"] == True
        assert result["payload"]["include_processes"] == False
    
    def test_validate_directory_scan_requires_path(self):
        """Test validation that directory scan requires path"""
        action = "run_scan"
        payload = {"scan_type": "directory"}  # Missing path
        
        with pytest.raises(ValueError, match="Directory scan requires 'path' parameter"):
            self.translator.validate_action_payload(action, payload)
    
    def test_validate_block_url_requires_url(self):
        """Test validation that block URL requires URL"""
        action = "block_url"
        payload = {}  # Missing URL
        
        with pytest.raises(ValueError, match="requires 'url' or 'urls' parameter"):
            self.translator.validate_action_payload(action, payload)
    
    def test_unsupported_action(self):
        """Test handling of unsupported action"""
        with pytest.raises(ValueError, match="Unsupported action"):
            self.translator.translate_action("invalid_action", {})
    
    def test_get_supported_actions(self):
        """Test getting list of supported actions"""
        actions = self.translator.get_supported_actions()
        
        assert "run_scan" in actions
        assert "block_url" in actions
        assert "install_patches" in actions
        assert "get_system_info" in actions
        assert len(actions) >= 8


class TestCommandSender:
    """Unit tests for CommandSender"""
    
    def setup_method(self):
        # Mock dependencies
        self.mock_connection_manager = Mock()
        self.mock_database = AsyncMock()
        
        self.sender = CommandSender(
            private_key_path=None,  # Will generate temp key
            connection_manager=self.mock_connection_manager,
            database=self.mock_database
        )
    
    def test_sign_command(self):
        """Test command signing"""
        command_data = {
            "command_id": "test-123",
            "command_type": "scan",
            "payload": {"scan_type": "quick"}
        }
        
        signature = self.sender._sign_command(command_data)
        
        assert isinstance(signature, str)
        assert len(signature) > 100  # Base64 signature should be substantial
    
    def test_create_signed_command(self):
        """Test creating a signed command"""
        command = self.sender._create_signed_command(
            agent_id="test-agent",
            command_type="scan",
            payload={"scan_type": "quick"},
            issued_by="admin@test.com",
            priority=3
        )
        
        assert "command_id" in command
        assert command["agent_id"] == "test-agent"
        assert command["command_type"] == "scan"
        assert command["payload"]["scan_type"] == "quick"
        assert command["issued_by"] == "admin@test.com"
        assert command["priority"] == 3
        assert "signature" in command
        assert "issued_at" in command
        assert "expires_at" in command
    
    @pytest.mark.asyncio
    async def test_send_command_agent_online(self):
        """Test sending command to online agent"""
        # Mock agent as online
        self.mock_connection_manager.is_agent_connected.return_value = True
        self.mock_connection_manager.send_to_agent = AsyncMock(return_value=True)
        self.mock_database.store_command = AsyncMock()
        self.mock_database.update_command_status = AsyncMock()
        
        command_id = await self.sender.send_command_to_agent(
            agent_id="test-agent",
            command_type="scan",
            payload={"scan_type": "quick"},
            issued_by="admin"
        )
        
        assert command_id is not None
        assert len(command_id) > 10  # UUID should be substantial
        
        # Verify database calls
        self.mock_database.store_command.assert_called_once()
        self.mock_database.update_command_status.assert_called()
        
        # Verify WebSocket send
        self.mock_connection_manager.send_to_agent.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_command_agent_offline(self):
        """Test sending command to offline agent"""
        # Mock agent as offline
        self.mock_connection_manager.is_agent_connected.return_value = False
        self.mock_database.store_command = AsyncMock()
        self.mock_database.update_command_status = AsyncMock()
        
        command_id = await self.sender.send_command_to_agent(
            agent_id="test-agent",
            command_type="scan",
            payload={"scan_type": "quick"}
        )
        
        assert command_id is not None
        
        # Command should be queued for offline agent
        command_info = self.sender.get_command_status(command_id)
        assert command_info["status"] == "queued"


class TestManagerBridge:
    """Unit tests for ManagerBridge"""
    
    def setup_method(self):
        # Mock command sender
        self.mock_sender = AsyncMock()
        self.bridge = ManagerBridge(self.mock_sender)
    
    @pytest.mark.asyncio
    async def test_execute_admin_action_success(self):
        """Test successful admin action execution"""
        # Mock successful command sending
        self.mock_sender.send_command_to_agent = AsyncMock(return_value="cmd-123")
        
        result = await self.bridge.execute_admin_action(
            agent_id="test-agent",
            action="run_scan",
            payload={"scan_type": "quick_system"},
            issued_by="admin"
        )
        
        assert result["success"] == True
        assert result["command_id"] == "cmd-123"
        assert result["status"] == "dispatched"
        
        # Verify sender was called with translated command
        self.mock_sender.send_command_to_agent.assert_called_once()
        call_args = self.mock_sender.send_command_to_agent.call_args
        assert call_args[1]["command_type"] == "scan"
        assert call_args[1]["payload"]["scan_type"] == "quick"
    
    @pytest.mark.asyncio
    async def test_execute_admin_action_validation_error(self):
        """Test admin action with validation error"""
        result = await self.bridge.execute_admin_action(
            agent_id="test-agent",
            action="run_scan",
            payload={"scan_type": "directory"},  # Missing required path
            issued_by="admin"
        )
        
        assert result["success"] == False
        assert "validation_error" in result["error_type"]
        assert "path" in result["error"]
    
    @pytest.mark.asyncio
    async def test_execute_bulk_action(self):
        """Test bulk action execution"""
        # Mock successful command sending
        self.mock_sender.send_command_to_agent = AsyncMock(return_value="cmd-123")
        
        result = await self.bridge.execute_bulk_action(
            agent_ids=["agent-1", "agent-2"],
            action="run_scan",
            payload={"scan_type": "quick_system"}
        )
        
        assert result["success"] == True
        assert result["total_agents"] == 2
        assert result["successful"] == 2
        assert result["failed"] == 0
        assert len(result["results"]) == 2
        
        # Verify sender was called for each agent
        assert self.mock_sender.send_command_to_agent.call_count == 2
    
    def test_get_supported_actions(self):
        """Test getting supported actions"""
        actions = self.bridge.get_supported_actions()
        assert isinstance(actions, list)
        assert "run_scan" in actions
        assert "block_url" in actions


class TestAdminActionHelpers:
    """Unit tests for AdminActionHelpers"""
    
    def test_create_scan_action(self):
        """Test creating scan action payload"""
        payload = AdminActionHelpers.create_scan_action(
            scan_type="full",
            path="/home/user",
            options={"heuristics": True}
        )
        
        assert payload["scan_type"] == "full"
        assert payload["path"] == "/home/user"
        assert payload["options"]["heuristics"] == True
    
    def test_create_web_block_action(self):
        """Test creating web block action payload"""
        payload = AdminActionHelpers.create_web_block_action(
            urls=["malicious.com", "phishing.org"],
            category="security_block"
        )
        
        assert payload["urls"] == ["malicious.com", "phishing.org"]
        assert payload["category"] == "security_block"
    
    def test_create_patch_install_action(self):
        """Test creating patch install action payload"""
        payload = AdminActionHelpers.create_patch_install_action(
            patch_ids=["KB123", "KB456"],
            auto_reboot=True
        )
        
        assert payload["patch_ids"] == ["KB123", "KB456"]
        assert payload["auto_reboot"] == True
        assert payload["backup_before_install"] == True
    
    def test_create_system_info_action(self):
        """Test creating system info action payload"""
        payload = AdminActionHelpers.create_system_info_action(
            include_network=False,
            include_processes=True
        )
        
        assert payload["include_network"] == False
        assert payload["include_processes"] == True
        assert payload["include_disk"] == True


if __name__ == "__main__":
    # Run unit tests
    pytest.main([__file__, "-v"])