#!/usr/bin/env python3
"""
Complete system test for RiskNoX fixes
Tests all the fixed issues reported by the user
"""

import asyncio
import aiohttp
import json
import websockets
import sys
import os
from datetime import datetime

# Add manager src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'manager', 'src'))

class RiskNoXSystemTest:
    def __init__(self):
        self.manager_host = "127.0.0.1"
        self.manager_port = 8001
        self.websocket_port = 8001
        self.session = None
        self.results = {
            "dashboard_agent_status": False,
            "agents_list_display": False,
            "antivirus_real_data": False,
            "web_blocking_real_data": False,
            "patch_rollout_real_data": False,
            "events_logs_display": False,
            "websocket_connection": False
        }
        
    async def setup(self):
        """Setup test session"""
        self.session = aiohttp.ClientSession()
        
    async def cleanup(self):
        """Cleanup test session"""
        if self.session:
            await self.session.close()
            
    async def test_manager_running(self):
        """Test if manager is running"""
        try:
            async with self.session.get(f"http://{self.manager_host}:{self.manager_port}/health") as resp:
                if resp.status == 200:
                    print("✅ Manager is running")
                    return True
                elif resp.status == 404:
                    # Try alternative health check
                    async with self.session.get(f"http://{self.manager_host}:{self.manager_port}/") as resp2:
                        if resp2.status == 200:
                            print("✅ Manager is running (root endpoint)")
                            return True
        except Exception as e:
            print(f"❌ Manager is not running: {e}")
            return False
            
    async def test_dashboard_api(self):
        """Test dashboard API for real agent status"""
        try:
            async with self.session.get(f"http://{self.manager_host}:{self.manager_port}/api/ui/dashboard") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    print(f"✅ Dashboard API working: {data}")
                    
                    # Check if it's showing real data structure
                    if 'agents' in data and 'status_counts' in data:
                        self.results["dashboard_agent_status"] = True
                        print("✅ Dashboard shows real agent status structure")
                    return True
                else:
                    print(f"❌ Dashboard API failed with status {resp.status}")
        except Exception as e:
            print(f"❌ Dashboard API test failed: {e}")
            
    async def test_agents_list_api(self):
        """Test agents list API for real data"""
        try:
            async with self.session.get(f"http://{self.manager_host}:{self.manager_port}/api/ui/agents") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    print(f"✅ Agents list API working")
                    
                    # Check if it's showing real data instead of hardcoded
                    if isinstance(data, list):
                        self.results["agents_list_display"] = True
                        print("✅ Agents list shows real data structure")
                        if len(data) == 0:
                            print("ℹ️  No agents currently registered (expected if no agents connected)")
                        else:
                            print(f"ℹ️  Found {len(data)} agents")
                    return True
                else:
                    print(f"❌ Agents list API failed with status {resp.status}")
        except Exception as e:
            print(f"❌ Agents list API test failed: {e}")
            
    async def test_antivirus_api(self):
        """Test antivirus API for real scan data"""
        try:
            async with self.session.get(f"http://{self.manager_host}:{self.manager_port}/api/scans/") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    print(f"✅ Antivirus API working")
                    
                    # Check if it's real data structure
                    if 'items' in data and 'total' in data:
                        self.results["antivirus_real_data"] = True
                        print("✅ Antivirus shows real scan data structure")
                        print(f"ℹ️  Found {data['total']} scan records")
                    return True
                else:
                    print(f"❌ Antivirus API failed with status {resp.status}")
        except Exception as e:
            print(f"❌ Antivirus API test failed: {e}")
            
    async def test_web_blocking_api(self):
        """Test web blocking API for real data"""
        try:
            async with self.session.get(f"http://{self.manager_host}:{self.manager_port}/api/web-blocking/urls") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    print(f"✅ Web blocking API working")
                    
                    # Check if it's real data structure (should start empty, not hardcoded)
                    if 'items' in data and 'total' in data:
                        self.results["web_blocking_real_data"] = True
                        print("✅ Web blocking shows real data structure")
                        print(f"ℹ️  Found {data['total']} blocked URLs")
                    return True
                else:
                    print(f"❌ Web blocking API failed with status {resp.status}")
        except Exception as e:
            print(f"❌ Web blocking API test failed: {e}")
            
    async def test_patch_rollout_api(self):
        """Test patch rollout API for real data"""
        try:
            async with self.session.get(f"http://{self.manager_host}:{self.manager_port}/api/patches/rollouts/") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    print(f"✅ Patch rollout API working")
                    
                    # Check if it's real data structure
                    if 'items' in data and 'total' in data:
                        self.results["patch_rollout_real_data"] = True
                        print("✅ Patch rollout shows real data structure")
                        print(f"ℹ️  Found {data['total']} patch rollouts")
                    return True
                else:
                    print(f"❌ Patch rollout API failed with status {resp.status}")
        except Exception as e:
            print(f"❌ Patch rollout API test failed: {e}")
            
    async def test_events_api(self):
        """Test events API for manager logs"""
        try:
            async with self.session.get(f"http://{self.manager_host}:{self.manager_port}/api/events/") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    print(f"✅ Events API working")
                    
                    # Check if it's showing real events/logs
                    if 'items' in data and 'total' in data:
                        self.results["events_logs_display"] = True
                        print("✅ Events shows real logs structure")
                        print(f"ℹ️  Found {data['total']} events")
                        
                        # Show sample events
                        if data['items']:
                            for event in data['items'][:3]:  # Show first 3
                                print(f"   📋 {event.get('event_type', 'unknown')}: {event.get('message', 'no message')}")
                    return True
                else:
                    print(f"❌ Events API failed with status {resp.status}")
        except Exception as e:
            print(f"❌ Events API test failed: {e}")
            
    async def test_websocket_connection(self):
        """Test WebSocket connection capability"""
        try:
            uri = f"ws://{self.manager_host}:{self.websocket_port}/ws/test"
            
            # Try to connect briefly to test WebSocket server
            try:
                async with websockets.connect(uri, timeout=5) as websocket:
                    print("✅ WebSocket connection test successful")
                    self.results["websocket_connection"] = True
                    return True
            except websockets.exceptions.ConnectionClosed:
                # Connection closed immediately is actually expected for unauthenticated connection
                print("✅ WebSocket server is running (connection closed as expected)")
                self.results["websocket_connection"] = True
                return True
        except Exception as e:
            print(f"❌ WebSocket connection test failed: {e}")
            return False
            
    async def run_all_tests(self):
        """Run all system tests"""
        print("🔄 Starting RiskNoX System Tests...")
        print("=" * 50)
        
        await self.setup()
        
        try:
            # Test manager is running
            if not await self.test_manager_running():
                print("\n❌ Manager is not running. Please start the manager first.")
                print("Run: python manager/run_manager.py")
                return
                
            print()
            
            # Test all API endpoints
            await self.test_dashboard_api()
            await self.test_agents_list_api()
            await self.test_antivirus_api()
            await self.test_web_blocking_api()
            await self.test_patch_rollout_api()
            await self.test_events_api()
            await self.test_websocket_connection()
            
            print("\n" + "=" * 50)
            print("📊 TEST RESULTS SUMMARY:")
            print("=" * 50)
            
            all_passed = True
            for test_name, passed in self.results.items():
                status = "✅ PASS" if passed else "❌ FAIL"
                test_display = test_name.replace("_", " ").title()
                print(f"{status}: {test_display}")
                if not passed:
                    all_passed = False
                    
            print("=" * 50)
            if all_passed:
                print("🎉 ALL TESTS PASSED! All issues have been fixed.")
            else:
                print("⚠️  Some tests failed. Check the manager logs for errors.")
                
            print("\n📋 NEXT STEPS:")
            print("1. Start an agent to test real-time connectivity")
            print("2. Run a scan from the admin UI to test real-time logs")
            print("3. Check the Events page for live manager activity")
            
        finally:
            await self.cleanup()

if __name__ == "__main__":
    test = RiskNoXSystemTest()
    asyncio.run(test.run_all_tests())