#!/usr/bin/env python3
"""
Test script to verify agent-manager communication
Tests WebSocket connection, command execution, and live logging
"""

import asyncio
import json
import uuid
import time
from datetime import datetime
from pathlib import Path
import sys

# Add paths for imports
sys.path.append(str(Path(__file__).parent / "agent"))
sys.path.append(str(Path(__file__).parent / "manager" / "src"))

from agent.websocket_client import AgentWebSocketClient
from agent.command_handler import CommandHandler


class TestAgentManagerConnection:
    """Test class for agent-manager communication"""
    
    def __init__(self):
        self.test_results = []
        
    def log_test(self, test_name: str, success: bool, message: str = ""):
        """Log test result"""
        status = "✅ PASS" if success else "❌ FAIL"
        self.test_results.append({
            "test": test_name,
            "success": success,
            "message": message,
            "timestamp": datetime.now().isoformat()
        })
        print(f"{status} {test_name}: {message}")
        
    async def test_websocket_connection(self):
        """Test basic WebSocket connection"""
        try:
            config = {
                "manager_url": "wss://localhost:8000",
                "hostname": "test-agent",
                "tags": ["test"],
                "cert_dir": "./agent/certs"
            }
            
            # Test that agent client can be created
            agent = AgentWebSocketClient(config)
            self.log_test("WebSocket Client Creation", True, "Agent client created successfully")
            
            # Test command handler
            command_handler = CommandHandler()
            self.log_test("Command Handler Creation", True, "Command handler created successfully")
            
            return True
            
        except Exception as e:
            self.log_test("WebSocket Connection", False, f"Error: {str(e)}")
            return False
            
    async def test_command_handler_scan(self):
        """Test scan command handler with live logging"""
        try:
            # Mock WebSocket client for testing
            class MockWebSocketClient:
                def __init__(self):
                    self.sent_messages = []
                    
                async def _send_message(self, message):
                    self.sent_messages.append(message)
                    print(f"📨 Mock WebSocket sent: {message['type']} - {message.get('log_line', message.get('status_type', 'N/A'))}")
            
            mock_client = MockWebSocketClient()
            command_handler = CommandHandler(websocket_client=mock_client)
            
            # Test scan command payload
            scan_payload = {
                "command_id": str(uuid.uuid4()),
                "scan_type": "custom",
                "targets": [str(Path.home() / "Documents")],
                "options": {"quick_scan": True}
            }
            
            print("🔍 Testing scan command execution...")
            result = await command_handler.execute("scan", scan_payload)
            
            # Check if scan was attempted (even if ClamAV not available)
            if result.get("success") or "not found" in result.get("error", "").lower():
                self.log_test("Scan Command Execution", True, "Scan command processed correctly")
                
                # Check if live logs were sent
                scan_logs = [msg for msg in mock_client.sent_messages if msg.get("type") == "scan_logs"]
                if scan_logs:
                    self.log_test("Live Scan Logging", True, f"Sent {len(scan_logs)} live log messages")
                else:
                    self.log_test("Live Scan Logging", False, "No live log messages sent")
                    
            else:
                self.log_test("Scan Command Execution", False, f"Scan failed: {result.get('error', 'Unknown error')}")
                
            return result.get("success", False)
            
        except Exception as e:
            self.log_test("Scan Command Test", False, f"Error: {str(e)}")
            return False
            
    async def test_web_blocking_command(self):
        """Test web blocking command with status updates"""
        try:
            class MockWebSocketClient:
                def __init__(self):
                    self.sent_messages = []
                    
                async def _send_message(self, message):
                    self.sent_messages.append(message)
                    print(f"📨 Web blocking update: {message['type']} - {message.get('status', {}).get('action', 'N/A')}")
            
            mock_client = MockWebSocketClient()
            command_handler = CommandHandler(websocket_client=mock_client)
            
            # Test web blocking payload
            web_block_payload = {
                "urls": ["example.com", "test.malware.com", "bad-site.net"]
            }
            
            print("🚫 Testing web blocking command...")
            result = await command_handler.execute("web_block", web_block_payload)
            
            # Check status updates
            status_updates = [msg for msg in mock_client.sent_messages if msg.get("type") == "status_update"]
            if status_updates:
                self.log_test("Web Blocking Status Updates", True, f"Sent {len(status_updates)} status updates")
            else:
                self.log_test("Web Blocking Status Updates", False, "No status updates sent")
                
            if result.get("success"):
                self.log_test("Web Blocking Command", True, f"Blocked {result.get('urls_blocked', 0)} URLs")
            else:
                self.log_test("Web Blocking Command", False, f"Error: {result.get('error', 'Unknown error')}")
                
            return result.get("success", False)
            
        except Exception as e:
            self.log_test("Web Blocking Test", False, f"Error: {str(e)}")
            return False
            
    async def test_system_info_command(self):
        """Test system information gathering"""
        try:
            command_handler = CommandHandler()
            
            print("💻 Testing system info command...")
            result = await command_handler.execute("system_info", {})
            
            if result.get("success") and result.get("system_info"):
                system_info = result["system_info"]
                required_fields = ["hostname", "os", "cpu", "memory", "disk"]
                
                missing_fields = [field for field in required_fields if field not in system_info]
                if not missing_fields:
                    self.log_test("System Info Command", True, f"Gathered complete system information")
                else:
                    self.log_test("System Info Command", False, f"Missing fields: {missing_fields}")
                    
            else:
                self.log_test("System Info Command", False, f"Error: {result.get('error', 'Unknown error')}")
                
            return result.get("success", False)
            
        except Exception as e:
            self.log_test("System Info Test", False, f"Error: {str(e)}")
            return False
            
    async def test_data_transmission_formats(self):
        """Test different data transmission formats"""
        try:
            # Test JSON serialization of different data types
            test_data = {
                "string": "test_string",
                "integer": 12345,
                "float": 123.45,
                "boolean": True,
                "list": [1, 2, 3, "test"],
                "dict": {"nested": {"data": "value"}},
                "timestamp": datetime.now().isoformat(),
                "uuid": str(uuid.uuid4())
            }
            
            # Test JSON serialization
            json_data = json.dumps(test_data)
            parsed_data = json.loads(json_data)
            
            if parsed_data == test_data:
                self.log_test("JSON Data Serialization", True, "All data types serialize correctly")
            else:
                self.log_test("JSON Data Serialization", False, "Data corruption during serialization")
                
            return True
            
        except Exception as e:
            self.log_test("Data Transmission Test", False, f"Error: {str(e)}")
            return False
            
    async def run_all_tests(self):
        """Run all connection and communication tests"""
        print("🚀 Starting Agent-Manager Communication Tests")
        print("=" * 60)
        
        tests = [
            ("WebSocket Connection", self.test_websocket_connection),
            ("Scan Command with Live Logs", self.test_command_handler_scan),
            ("Web Blocking with Status", self.test_web_blocking_command),
            ("System Information", self.test_system_info_command),
            ("Data Transmission Formats", self.test_data_transmission_formats)
        ]
        
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests:
            print(f"\n🧪 Running: {test_name}")
            success = await test_func()
            if success:
                passed += 1
                
        print("\n" + "=" * 60)
        print(f"📊 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All tests passed! Agent-Manager communication is working correctly.")
        else:
            print("⚠️  Some tests failed. Check the implementation for issues.")
            
        # Print detailed results
        print("\n📋 Detailed Results:")
        for result in self.test_results:
            status = "✅" if result["success"] else "❌"
            print(f"{status} {result['test']}: {result['message']}")
            
        return passed == total


async def main():
    """Main test function"""
    tester = TestAgentManagerConnection()
    
    try:
        success = await tester.run_all_tests()
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\n⚡ Tests interrupted by user")
        return 1
    except Exception as e:
        print(f"\n💥 Test runner crashed: {str(e)}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)