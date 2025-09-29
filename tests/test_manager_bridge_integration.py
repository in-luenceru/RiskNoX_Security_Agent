"""
Integration Tests for Manager Bridge
Tests the end-to-end flow: Admin UI → Manager Bridge → Agent
"""

import pytest
import asyncio
import json
import requests
from datetime import datetime
import uuid
import logging

from agent_emulator import AgentEmulator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestManagerBridge:
    """Integration tests for Manager Bridge functionality"""
    
    def __init__(self, manager_host="localhost", manager_port=8000, ws_port=8444):
        self.manager_host = manager_host
        self.manager_port = manager_port
        self.ws_port = ws_port
        self.base_url = f"http://{manager_host}:{manager_port}"
        self.agents = {}
        self.admin_token = None
    
    async def setup(self):
        """Set up test environment"""
        logger.info("Setting up integration test environment")
        
        # Get admin token (assuming basic auth for testing)
        # In production, this would use proper authentication
        self.admin_token = "test-admin-token"  # Placeholder
        
        # Create test agents
        for i in range(2):
            agent_id = f"test-agent-{i+1}"
            agent = AgentEmulator(agent_id, self.manager_host, self.ws_port)
            self.agents[agent_id] = agent
    
    async def teardown(self):
        """Clean up test environment"""
        logger.info("Tearing down integration test environment")
        
        # Disconnect all agents
        for agent in self.agents.values():
            if agent.running:
                await agent.disconnect()
    
    async def connect_agents(self):
        """Connect all test agents to Manager"""
        logger.info("Connecting test agents to Manager")
        
        # Connect agents in parallel
        connect_tasks = []
        for agent in self.agents.values():
            connect_tasks.append(agent.connect())
        
        try:
            await asyncio.wait_for(
                asyncio.gather(*connect_tasks, return_exceptions=True),
                timeout=10.0
            )
            
            # Wait a moment for connections to stabilize
            await asyncio.sleep(2)
            
            logger.info(f"Connected {len(self.agents)} test agents")
        except asyncio.TimeoutError:
            logger.error("Timeout connecting agents")
            raise
    
    def _make_api_request(self, method: str, endpoint: str, data=None):
        """Make API request to Manager"""
        url = f"{self.base_url}{endpoint}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.admin_token}"
        }
        
        if method.upper() == "GET":
            response = requests.get(url, headers=headers)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers, json=data)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        response.raise_for_status()
        return response.json()
    
    async def test_scan_command(self):
        """Test scan command flow: Admin → Manager → Agent → Response"""
        logger.info("Testing scan command flow")
        
        # Connect agents
        await self.connect_agents()
        
        # Get first agent for testing
        agent_id = list(self.agents.keys())[0]
        agent = self.agents[agent_id]
        
        # Clear agent history
        agent.clear_history()
        
        # Trigger scan via Manager admin API
        scan_payload = {
            "agent_id": agent_id,
            "action": "run_scan",
            "payload": {
                "scan_type": "quick_system",
                "options": {"heuristics": True}
            },
            "priority": 3
        }
        
        try:
            # Send admin action to Manager
            response = self._make_api_request("POST", "/admin/action/trigger", scan_payload)
            
            assert response["success"] == True
            assert "command_id" in response
            command_id = response["command_id"]
            
            logger.info(f"Scan command dispatched: {command_id}")
            
            # Wait for agent to process command
            await asyncio.sleep(5)
            
            # Verify agent received and processed command
            received_commands = agent.get_received_commands()
            assert len(received_commands) >= 1
            
            # Find our scan command
            scan_command = None
            for cmd in received_commands:
                if cmd.get("command_id") == command_id:
                    scan_command = cmd
                    break
            
            assert scan_command is not None, "Agent did not receive scan command"
            assert scan_command["command_type"] == "scan"
            assert scan_command["payload"]["scan_type"] == "quick"
            
            # Verify command response
            command_response = agent.get_command_response(command_id)
            assert command_response is not None, "Agent did not send command response"
            assert command_response["success"] == True
            assert "files_scanned" in command_response
            
            logger.info(f"Scan command completed successfully: {command_response['files_scanned']} files scanned")
            
            # Check command status via Manager API
            status_response = self._make_api_request("GET", f"/admin/command/{command_id}/status")
            assert status_response["command_id"] == command_id
            assert status_response["status"] in ["completed", "sent"]  # Depending on timing
            
            return True
            
        except Exception as e:
            logger.error(f"Scan command test failed: {e}")
            raise
    
    async def test_web_blocking_command(self):
        """Test web blocking command flow"""
        logger.info("Testing web blocking command flow")
        
        # Connect agents
        await self.connect_agents()
        
        agent_id = list(self.agents.keys())[0]
        agent = self.agents[agent_id]
        agent.clear_history()
        
        # Test URL blocking
        block_payload = {
            "agent_id": agent_id,
            "action": "block_url",
            "payload": {
                "urls": ["malicious-site.com", "phishing-site.org"]
            }
        }
        
        try:
            # Send block command
            response = self._make_api_request("POST", "/admin/action/trigger", block_payload)
            assert response["success"] == True
            command_id = response["command_id"]
            
            # Wait for processing
            await asyncio.sleep(3)
            
            # Verify agent processed command
            received_commands = agent.get_received_commands()
            block_command = None
            for cmd in received_commands:
                if cmd.get("command_id") == command_id:
                    block_command = cmd
                    break
            
            assert block_command is not None
            assert block_command["command_type"] == "web_block"
            assert "malicious-site.com" in block_command["payload"]["urls"]
            
            # Verify response
            command_response = agent.get_command_response(command_id)
            assert command_response["success"] == True
            assert command_response["urls_blocked"] == 2
            
            logger.info("Web blocking command completed successfully")
            
            # Test URL listing
            agent.clear_history()
            list_payload = {
                "agent_id": agent_id,
                "action": "get_blocked_urls",
                "payload": {}
            }
            
            response = self._make_api_request("POST", "/admin/action/trigger", list_payload)
            command_id = response["command_id"]
            
            await asyncio.sleep(2)
            
            command_response = agent.get_command_response(command_id)
            assert command_response["success"] == True
            assert command_response["total_count"] == 2
            
            logger.info("Web blocking list command completed successfully")
            
            return True
            
        except Exception as e:
            logger.error(f"Web blocking test failed: {e}")
            raise
    
    async def test_bulk_scan_command(self):
        """Test bulk scan command on multiple agents"""
        logger.info("Testing bulk scan command")
        
        # Connect agents
        await self.connect_agents()
        
        # Clear all agent histories
        for agent in self.agents.values():
            agent.clear_history()
        
        # Send bulk scan command
        bulk_payload = {
            "agent_ids": list(self.agents.keys()),
            "action": "run_scan",
            "payload": {
                "scan_type": "quick_system"
            }
        }
        
        try:
            response = self._make_api_request("POST", "/admin/action/bulk", bulk_payload)
            assert response["success"] == True
            assert response["total_agents"] == len(self.agents)
            assert response["successful"] == len(self.agents)
            
            # Wait for processing
            await asyncio.sleep(5)
            
            # Verify all agents received and processed commands
            for agent_id, agent in self.agents.items():
                received_commands = agent.get_received_commands()
                assert len(received_commands) >= 1
                
                # Find scan command
                scan_command = None
                for cmd in received_commands:
                    if cmd["command_type"] == "scan":
                        scan_command = cmd
                        break
                
                assert scan_command is not None, f"Agent {agent_id} did not receive scan command"
                
                # Verify response
                command_response = agent.get_command_response(scan_command["command_id"])
                assert command_response is not None
                assert command_response["success"] == True
            
            logger.info(f"Bulk scan completed successfully on {len(self.agents)} agents")
            return True
            
        except Exception as e:
            logger.error(f"Bulk scan test failed: {e}")
            raise
    
    async def test_offline_agent_command_queuing(self):
        """Test command queuing for offline agents"""
        logger.info("Testing offline agent command queuing")
        
        # Connect one agent
        agent_id = list(self.agents.keys())[0]
        agent = self.agents[agent_id]
        
        # Connect agent temporarily
        await agent.connect()
        await asyncio.sleep(1)
        
        # Disconnect agent
        await agent.disconnect()
        await asyncio.sleep(1)
        
        # Send command to offline agent
        scan_payload = {
            "agent_id": agent_id,
            "action": "run_scan",
            "payload": {"scan_type": "quick_system"}
        }
        
        try:
            response = self._make_api_request("POST", "/admin/action/trigger", scan_payload)
            assert response["success"] == True
            command_id = response["command_id"]
            
            logger.info(f"Command sent to offline agent: {command_id}")
            
            # Command should be queued since agent is offline
            await asyncio.sleep(2)
            
            # Reconnect agent
            agent.clear_history()
            await agent.connect()
            
            # Wait for queued command delivery
            await asyncio.sleep(3)
            
            # Verify agent received queued command
            received_commands = agent.get_received_commands()
            assert len(received_commands) >= 1
            
            queued_command = None
            for cmd in received_commands:
                if cmd.get("command_id") == command_id:
                    queued_command = cmd
                    break
            
            assert queued_command is not None, "Agent did not receive queued command"
            assert queued_command["command_type"] == "scan"
            
            logger.info("Offline agent command queuing test completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Offline agent test failed: {e}")
            raise
    
    async def test_system_info_command(self):
        """Test system info command"""
        logger.info("Testing system info command")
        
        # Connect agents
        await self.connect_agents()
        
        agent_id = list(self.agents.keys())[0]
        agent = self.agents[agent_id]
        agent.clear_history()
        
        # Send system info command
        info_payload = {
            "agent_id": agent_id,
            "action": "get_system_info",
            "payload": {
                "include_network": True,
                "include_disk": True
            }
        }
        
        try:
            response = self._make_api_request("POST", "/admin/action/trigger", info_payload)
            assert response["success"] == True
            command_id = response["command_id"]
            
            # Wait for processing
            await asyncio.sleep(3)
            
            # Verify command response
            command_response = agent.get_command_response(command_id)
            assert command_response is not None
            assert command_response["success"] == True
            assert "system_info" in command_response
            assert "hostname" in command_response["system_info"]
            
            logger.info("System info command completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"System info test failed: {e}")
            raise


async def run_integration_tests():
    """Run all integration tests"""
    logger.info("Starting Manager Bridge integration tests")
    
    test_suite = TestManagerBridge()
    
    try:
        await test_suite.setup()
        
        # Run tests
        tests = [
            test_suite.test_scan_command,
            test_suite.test_web_blocking_command,
            test_suite.test_bulk_scan_command,
            test_suite.test_offline_agent_command_queuing,
            test_suite.test_system_info_command
        ]
        
        passed = 0
        failed = 0
        
        for test in tests:
            test_name = test.__name__
            try:
                logger.info(f"Running test: {test_name}")
                result = await test()
                if result:
                    logger.info(f"✅ {test_name} PASSED")
                    passed += 1
                else:
                    logger.error(f"❌ {test_name} FAILED")
                    failed += 1
            except Exception as e:
                logger.error(f"❌ {test_name} FAILED: {e}")
                failed += 1
            
            # Small delay between tests
            await asyncio.sleep(1)
        
        logger.info(f"Integration tests completed: {passed} passed, {failed} failed")
        
        if failed == 0:
            logger.info("🎉 All integration tests passed!")
        else:
            logger.error(f"❌ {failed} tests failed")
        
        return failed == 0
        
    finally:
        await test_suite.teardown()


if __name__ == "__main__":
    # Run integration tests
    success = asyncio.run(run_integration_tests())
    exit(0 if success else 1)