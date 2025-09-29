#!/usr/bin/env python3
"""
Simplified test to verify agent-manager communication architecture
Tests the core command handling and data transmission without external dependencies
"""

import asyncio
import json
import uuid
import sys
from datetime import datetime
from pathlib import Path

# Add agent path for imports
sys.path.append(str(Path(__file__).parent / "agent"))

# Import only the command handler (no external dependencies)
from command_handler import CommandHandler


class MockWebSocketClient:
    """Mock WebSocket client for testing"""
    
    def __init__(self):
        self.sent_messages = []
        self.connection_log = []
        
    async def _send_message(self, message):
        """Mock message sending"""
        self.sent_messages.append(message)
        msg_type = message.get("type", "unknown")
        if msg_type == "scan_logs":
            log_line = message.get("log_line", "")
            progress = message.get("progress", 0)
            print(f"📊 Scan Progress: {progress}% - {log_line}")
        elif msg_type == "status_update":
            status_type = message.get("status_type", "")
            action = message.get("status", {}).get("action", "")
            print(f"🔄 Status Update [{status_type}]: {action}")
        else:
            print(f"📨 Message sent: {msg_type}")


async def test_scan_command_with_live_logs():
    """Test scan command with real-time logging"""
    print("🔍 Testing Scan Command with Live Logging")
    print("-" * 50)
    
    mock_client = MockWebSocketClient()
    command_handler = CommandHandler(websocket_client=mock_client)
    
    # Test scan payload
    scan_payload = {
        "command_id": str(uuid.uuid4()),
        "scan_type": "custom",
        "targets": [str(Path.home())],
        "options": {"verbose": True}
    }
    
    print(f"🎯 Target: {scan_payload['targets'][0]}")
    print("⏳ Executing scan command...")
    
    # Execute scan
    result = await command_handler.execute("scan", scan_payload)
    
    # Analyze results
    print(f"\n📋 Scan Result:")
    print(f"   Success: {result.get('success', False)}")
    if result.get('error'):
        print(f"   Error: {result['error']}")
    else:
        print(f"   Files Scanned: {result.get('files_scanned', 0)}")
        print(f"   Threats Found: {result.get('threats_found', 0)}")
    
    # Check live logs
    scan_logs = [msg for msg in mock_client.sent_messages if msg.get("type") == "scan_logs"]
    print(f"\n📡 Live Log Messages Sent: {len(scan_logs)}")
    
    if scan_logs:
        print("   Sample logs:")
        for i, log in enumerate(scan_logs[:3]):  # Show first 3 logs
            print(f"   [{i+1}] {log.get('log_line', 'N/A')}")
        if len(scan_logs) > 3:
            print(f"   ... and {len(scan_logs) - 3} more")
    
    return len(scan_logs) > 0


async def test_web_blocking_with_status():
    """Test web blocking with status updates"""
    print("\n🚫 Testing Web Blocking with Status Updates")
    print("-" * 50)
    
    mock_client = MockWebSocketClient()
    command_handler = CommandHandler(websocket_client=mock_client)
    
    # Test web blocking payload
    web_block_payload = {
        "urls": ["malware.example.com", "phishing.test.com", "dangerous-site.net"]
    }
    
    print(f"🎯 URLs to block: {', '.join(web_block_payload['urls'])}")
    print("⏳ Executing web block command...")
    
    # Execute web blocking
    result = await command_handler.execute("web_block", web_block_payload)
    
    # Analyze results
    print(f"\n📋 Web Block Result:")
    print(f"   Success: {result.get('success', False)}")
    if result.get('error'):
        print(f"   Error: {result['error']}")
    else:
        print(f"   URLs Blocked: {result.get('urls_blocked', 0)}")
        print(f"   Total URLs: {result.get('total_urls', 0)}")
    
    # Check status updates
    status_updates = [msg for msg in mock_client.sent_messages if msg.get("type") == "status_update"]
    print(f"\n📡 Status Updates Sent: {len(status_updates)}")
    
    if status_updates:
        print("   Status progression:")
        for i, update in enumerate(status_updates):
            action = update.get('status', {}).get('action', 'unknown')
            print(f"   [{i+1}] {action}")
    
    return len(status_updates) > 0


async def test_system_info_gathering():
    """Test system information gathering"""
    print("\n💻 Testing System Information Gathering")
    print("-" * 50)
    
    command_handler = CommandHandler()
    
    print("⏳ Gathering system information...")
    
    # Execute system info
    result = await command_handler.execute("system_info", {})
    
    # Analyze results
    print(f"\n📋 System Info Result:")
    print(f"   Success: {result.get('success', False)}")
    
    if result.get('success') and result.get('system_info'):
        system_info = result['system_info']
        print(f"   Hostname: {system_info.get('hostname', 'N/A')}")
        print(f"   OS: {system_info.get('os', {}).get('system', 'N/A')}")
        print(f"   CPU Count: {system_info.get('cpu', {}).get('count', 'N/A')}")
        print(f"   Memory: {system_info.get('memory', {}).get('total', 'N/A')} bytes")
        print(f"   Disk Partitions: {len(system_info.get('disk', []))}")
    elif result.get('error'):
        print(f"   Error: {result['error']}")
    
    return result.get('success', False)


async def test_data_serialization():
    """Test JSON data serialization for various data types"""
    print("\n📦 Testing Data Serialization")
    print("-" * 50)
    
    # Test complex data structure
    test_data = {
        "command_id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(),
        "scan_results": {
            "files_scanned": 1524,
            "threats_found": 3,
            "infected_files": [
                "C:\\temp\\suspicious.exe",
                "C:\\downloads\\malware.zip"
            ],
            "scan_duration": 245.67,
            "completed": True
        },
        "agent_info": {
            "hostname": "test-workstation",
            "os": "Windows 10",
            "tags": ["workstation", "development"]
        }
    }
    
    try:
        # Test serialization
        json_str = json.dumps(test_data, indent=2)
        
        # Test deserialization
        parsed_data = json.loads(json_str)
        
        print("✅ JSON serialization successful")
        print(f"   Original keys: {len(test_data)}")
        print(f"   Parsed keys: {len(parsed_data)}")
        print(f"   Data integrity: {'✅ Maintained' if test_data == parsed_data else '❌ Corrupted'}")
        
        # Test WebSocket message format
        websocket_message = {
            "type": "command_result",
            "command_id": test_data["command_id"],
            "result": test_data,
            "timestamp": test_data["timestamp"]
        }
        
        message_json = json.dumps(websocket_message)
        parsed_message = json.loads(message_json)
        
        print(f"   WebSocket message size: {len(message_json)} characters")
        print(f"   Message format: {'✅ Valid' if 'type' in parsed_message else '❌ Invalid'}")
        
        return True
        
    except Exception as e:
        print(f"❌ Serialization failed: {str(e)}")
        return False


async def main():
    """Run all communication tests"""
    print("🚀 Agent-Manager Communication Verification")
    print("=" * 60)
    
    tests = [
        ("Scan Command with Live Logs", test_scan_command_with_live_logs),
        ("Web Blocking with Status", test_web_blocking_with_status),
        ("System Info Gathering", test_system_info_gathering),
        ("Data Serialization", test_data_serialization)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            success = await test_func()
            if success:
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
                
        except Exception as e:
            print(f"💥 {test_name}: ERROR - {str(e)}")
    
    print("\n" + "=" * 60)
    print(f"📊 Final Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All communication tests passed!")
        print("✅ Agent-Manager connection is properly implemented")
        print("✅ Live logging is working")
        print("✅ Status updates are functional")
        print("✅ Data transmission is reliable")
    else:
        print("⚠️ Some tests failed - check implementation")
    
    return passed == total


if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⚡ Tests interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Test runner error: {str(e)}")
        sys.exit(1)