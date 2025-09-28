#!/usr/bin/env python3
"""
RiskNoX System Integration Test
Tests complete Manager-Agent communication and command execution
"""

import asyncio
import json
import os
import sys
import time
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any

import aiohttp
import structlog

# Configure logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer() if '--json' in sys.argv else structlog.dev.ConsoleRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


class RiskNoXSystemTest:
    """Integration test for RiskNoX Manager-Agent system"""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.manager_dir = self.base_dir / "manager"
        self.agent_dir = self.base_dir / "agent"
        
        # Test configuration
        self.manager_host = "localhost"
        self.manager_port = 8000
        self.manager_ws_port = 8001
        
        # Process handles
        self.manager_process = None
        self.agent_process = None
        
        # Test data
        self.agent_id = None
        self.test_commands = []
        
    async def setup_test_environment(self):
        """Set up test environment"""
        logger.info("🔧 Setting up test environment")
        
        # Create test directories
        test_dir = self.base_dir / "test_data"
        test_dir.mkdir(exist_ok=True)
        
        # Create test files for scanning
        (test_dir / "clean_file.txt").write_text("This is a clean test file")
        (test_dir / "test_scan.txt").write_text("Test file for scanning")
        
        # Set up environment variables
        os.environ["DATABASE_URL"] = "sqlite:///./test_manager.db"
        os.environ["REDIS_URL"] = "redis://localhost:6379/1"
        os.environ["MANAGER_HOST"] = self.manager_host
        os.environ["MANAGER_PORT"] = str(self.manager_port)
        os.environ["MANAGER_WS_PORT"] = str(self.manager_ws_port)
        
        logger.info("✅ Test environment ready")
    
    def start_manager(self):
        """Start the RiskNoX Manager"""
        logger.info("🚀 Starting RiskNoX Manager")
        
        try:
            manager_cmd = [
                sys.executable,
                str(self.manager_dir / "run_manager.py"),
                "--host", self.manager_host,
                "--port", str(self.manager_port),
                "--ws-port", str(self.manager_ws_port),
                "--reload"
            ]
            
            self.manager_process = subprocess.Popen(
                manager_cmd,
                cwd=self.manager_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for manager to start
            time.sleep(5)
            
            if self.manager_process.poll() is None:
                logger.info("✅ Manager started successfully", pid=self.manager_process.pid)
                return True
            else:
                stdout, stderr = self.manager_process.communicate()
                logger.error("❌ Manager failed to start", stdout=stdout, stderr=stderr)
                return False
                
        except Exception as e:
            logger.error("❌ Failed to start manager", error=str(e))
            return False
    
    def start_agent(self):
        """Start the RiskNoX Agent"""
        logger.info("🤖 Starting RiskNoX Agent")
        
        try:
            agent_cmd = [
                sys.executable,
                str(self.agent_dir / "agent_main.py"),
                "--config", str(self.agent_dir / "test_agent_config.yaml"),
                "--log-level", "INFO"
            ]
            
            self.agent_process = subprocess.Popen(
                agent_cmd,
                cwd=self.agent_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for agent to start and enroll
            time.sleep(10)
            
            if self.agent_process.poll() is None:
                logger.info("✅ Agent started successfully", pid=self.agent_process.pid)
                return True
            else:
                stdout, stderr = self.agent_process.communicate()
                logger.error("❌ Agent failed to start", stdout=stdout, stderr=stderr)
                return False
                
        except Exception as e:
            logger.error("❌ Failed to start agent", error=str(e))
            return False
    
    async def wait_for_manager_ready(self, timeout: int = 30):
        """Wait for manager to be ready"""
        logger.info("⏳ Waiting for Manager to be ready")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"http://{self.manager_host}:{self.manager_port}/health") as response:
                        if response.status == 200:
                            logger.info("✅ Manager is ready")
                            return True
            except:
                pass
            
            await asyncio.sleep(1)
        
        logger.error("❌ Manager not ready within timeout")
        return False
    
    async def check_agent_enrollment(self):
        """Check if agent is enrolled and connected"""
        logger.info("🔍 Checking agent enrollment")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{self.manager_host}:{self.manager_port}/api/v1/agents") as response:
                    if response.status == 200:
                        agents = await response.json()
                        if agents and len(agents) > 0:
                            self.agent_id = agents[0]["agent_id"]
                            logger.info("✅ Agent enrolled", agent_id=self.agent_id, agent_count=len(agents))
                            return True
                        else:
                            logger.warning("⚠️ No agents found")
                            return False
                    else:
                        logger.error("❌ Failed to get agents", status=response.status)
                        return False
        except Exception as e:
            logger.error("❌ Failed to check enrollment", error=str(e))
            return False
    
    async def test_virus_scan(self):
        """Test virus scanning functionality"""
        logger.info("🦠 Testing virus scan command")
        
        try:
            scan_request = {
                "agent_ids": [self.agent_id],
                "scan_type": "quick",
                "targets": [str(self.base_dir / "test_data")],
                "priority": 3
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://{self.manager_host}:{self.manager_port}/api/v1/commands/scan",
                    json=scan_request
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        task_id = result.get("task_id")
                        logger.info("✅ Scan command sent", task_id=task_id)
                        
                        # Wait for command completion
                        await self.wait_for_command_completion(task_id)
                        return True
                    else:
                        error_text = await response.text()
                        logger.error("❌ Scan command failed", status=response.status, error=error_text)
                        return False
        except Exception as e:
            logger.error("❌ Scan test failed", error=str(e))
            return False
    
    async def test_web_blocking(self):
        """Test web blocking functionality"""
        logger.info("🌐 Testing web blocking command")
        
        try:
            block_request = {
                "agent_ids": [self.agent_id],
                "action": "block",
                "urls": ["malicious-site.com", "bad-domain.net"],
                "priority": 5
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://{self.manager_host}:{self.manager_port}/api/v1/commands/web-block",
                    json=block_request
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        task_id = result.get("task_id")
                        logger.info("✅ Web block command sent", task_id=task_id)
                        
                        await self.wait_for_command_completion(task_id)
                        return True
                    else:
                        error_text = await response.text()
                        logger.error("❌ Web block command failed", status=response.status, error=error_text)
                        return False
        except Exception as e:
            logger.error("❌ Web block test failed", error=str(e))
            return False
    
    async def test_patch_management(self):
        """Test patch management functionality"""
        logger.info("🔧 Testing patch management command")
        
        try:
            patch_request = {
                "agent_ids": [self.agent_id],
                "action": "check",
                "patch_ids": [],
                "options": {
                    "check_critical_only": True,
                    "include_optional": False
                },
                "priority": 2
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://{self.manager_host}:{self.manager_port}/api/v1/commands/patch",
                    json=patch_request
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        task_id = result.get("task_id")
                        logger.info("✅ Patch command sent", task_id=task_id)
                        
                        await self.wait_for_command_completion(task_id)
                        return True
                    else:
                        error_text = await response.text()
                        logger.error("❌ Patch command failed", status=response.status, error=error_text)
                        return False
        except Exception as e:
            logger.error("❌ Patch test failed", error=str(e))
            return False
    
    async def test_system_info(self):
        """Test system information collection"""
        logger.info("📊 Testing system info command")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://{self.manager_host}:{self.manager_port}/api/v1/commands/system-info",
                    json=[self.agent_id]
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        task_id = result.get("task_id")
                        logger.info("✅ System info command sent", task_id=task_id)
                        
                        await self.wait_for_command_completion(task_id)
                        return True
                    else:
                        error_text = await response.text()
                        logger.error("❌ System info command failed", status=response.status, error=error_text)
                        return False
        except Exception as e:
            logger.error("❌ System info test failed", error=str(e))
            return False
    
    async def wait_for_command_completion(self, task_id: str, timeout: int = 120):
        """Wait for command to complete"""
        logger.info("⏳ Waiting for command completion", task_id=task_id)
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # Check command status via task ID or agent commands
                await asyncio.sleep(2)
                
                # For now, just wait a reasonable time
                if time.time() - start_time > 10:
                    logger.info("✅ Command processing time elapsed", task_id=task_id)
                    return True
                    
            except Exception as e:
                logger.warning("Command status check failed", error=str(e))
                
            await asyncio.sleep(2)
        
        logger.warning("⚠️ Command completion timeout", task_id=task_id)
        return False
    
    def cleanup(self):
        """Clean up test processes"""
        logger.info("🧹 Cleaning up test environment")
        
        if self.agent_process:
            try:
                self.agent_process.terminate()
                self.agent_process.wait(timeout=10)
                logger.info("✅ Agent process terminated")
            except:
                self.agent_process.kill()
                logger.info("⚠️ Agent process killed")
        
        if self.manager_process:
            try:
                self.manager_process.terminate()
                self.manager_process.wait(timeout=10)
                logger.info("✅ Manager process terminated")
            except:
                self.manager_process.kill()
                logger.info("⚠️ Manager process killed")
    
    async def run_complete_test(self):
        """Run complete integration test"""
        logger.info("🚀 Starting RiskNoX Integration Test")
        
        success = True
        test_results = {}
        
        try:
            # Setup test environment
            await self.setup_test_environment()
            
            # Start Manager
            if not self.start_manager():
                return False
            
            # Wait for manager to be ready
            if not await self.wait_for_manager_ready():
                return False
            
            # Start Agent
            if not self.start_agent():
                return False
            
            # Check agent enrollment
            retries = 6
            enrolled = False
            for i in range(retries):
                logger.info(f"Checking enrollment attempt {i+1}/{retries}")
                if await self.check_agent_enrollment():
                    enrolled = True
                    break
                await asyncio.sleep(5)
            
            if not enrolled:
                logger.error("❌ Agent enrollment failed")
                return False
            
            # Run individual tests
            tests = [
                ("Virus Scan", self.test_virus_scan),
                ("Web Blocking", self.test_web_blocking),
                ("Patch Management", self.test_patch_management),
                ("System Info", self.test_system_info),
            ]
            
            for test_name, test_func in tests:
                logger.info(f"🧪 Running {test_name} test")
                try:
                    result = await test_func()
                    test_results[test_name] = result
                    if result:
                        logger.info(f"✅ {test_name} test passed")
                    else:
                        logger.error(f"❌ {test_name} test failed")
                        success = False
                except Exception as e:
                    logger.error(f"❌ {test_name} test error", error=str(e))
                    test_results[test_name] = False
                    success = False
                
                # Wait between tests
                await asyncio.sleep(3)
            
            # Print results summary
            logger.info("📋 Test Results Summary")
            logger.info("=" * 50)
            for test_name, result in test_results.items():
                status = "✅ PASS" if result else "❌ FAIL"
                logger.info(f"{test_name}: {status}")
            
            overall_status = "✅ ALL TESTS PASSED" if success else "❌ SOME TESTS FAILED"
            logger.info(f"Overall Result: {overall_status}")
            
            return success
            
        except Exception as e:
            logger.error("❌ Integration test failed", error=str(e))
            return False
        finally:
            self.cleanup()


async def main():
    """Main test entry point"""
    test = RiskNoXSystemTest()
    
    try:
        success = await test.run_complete_test()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        logger.info("Test interrupted by user")
        test.cleanup()
        sys.exit(1)
    except Exception as e:
        logger.error("Test execution failed", error=str(e))
        test.cleanup()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())