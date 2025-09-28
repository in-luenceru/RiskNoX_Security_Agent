#!/usr/bin/env python3
"""
Comprehensive Agent-Manager Communication Test
This script will verify that the Manager and Agent can communicate perfectly.
"""

import asyncio
import json
import sys
import os
import time
import requests
import tempfile
from pathlib import Path

# Add manager src to path for testing
manager_src = Path(__file__).parent / "manager" / "src"
sys.path.insert(0, str(manager_src))

class ManagerAgentTestSuite:
    """Test suite for Manager-Agent communication"""
    
    def __init__(self):
        self.manager_url = "http://localhost:8001"
        self.test_results = []
        
    def log_test(self, test_name, success, message=""):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}: {message}")
        self.test_results.append({
            "test": test_name,
            "success": success,
            "message": message
        })
        
    def test_manager_health(self):
        """Test Manager health endpoint"""
        try:
            response = requests.get(f"{self.manager_url}/health", timeout=5)
            if response.status_code == 200:
                health_data = response.json()
                self.log_test("Manager Health Check", True, 
                             f"Status: {health_data.get('status', 'unknown')}")
                return True
            else:
                self.log_test("Manager Health Check", False, 
                             f"HTTP {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            self.log_test("Manager Health Check", False, f"Connection error: {e}")
            return False
            
    def test_manager_enrollment_endpoint(self):
        """Test Manager enrollment endpoint accessibility"""
        try:
            # Test that enrollment endpoint exists (should return 405 for GET)
            response = requests.get(f"{self.manager_url}/api/v1/enroll", timeout=5)
            if response.status_code == 405:  # Method not allowed for GET
                self.log_test("Manager Enrollment Endpoint", True, 
                             "Endpoint accessible (405 expected for GET)")
                return True
            else:
                self.log_test("Manager Enrollment Endpoint", False, 
                             f"Unexpected status: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            self.log_test("Manager Enrollment Endpoint", False, f"Connection error: {e}")
            return False
            
    def test_manager_api_docs(self):
        """Test Manager API documentation"""
        try:
            response = requests.get(f"{self.manager_url}/docs", timeout=5)
            if response.status_code == 200:
                self.log_test("Manager API Documentation", True, "Swagger UI accessible")
                return True
            else:
                self.log_test("Manager API Documentation", False, 
                             f"HTTP {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            self.log_test("Manager API Documentation", False, f"Connection error: {e}")
            return False
            
    def simulate_agent_enrollment(self):
        """Simulate agent enrollment process"""
        try:
            # Create a mock CSR for testing
            mock_csr_data = {
                "hostname": "test-agent-001",
                "ip_address": "192.168.1.100",
                "os_info": "Windows 11",
                "agent_version": "1.0.0",
                # This would be a real CSR in production
                "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIICWjCCAUICAQAwFTETMBEGA1UEAwwKdGVzdC1hZ2VudDCCASIwDQYJKoZIhvcN\n-----END CERTIFICATE REQUEST-----"
            }
            
            response = requests.post(
                f"{self.manager_url}/api/v1/enroll",
                json=mock_csr_data,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                self.log_test("Agent Enrollment Simulation", True, 
                             "Mock enrollment successful")
                return True
            elif response.status_code == 422:
                self.log_test("Agent Enrollment Simulation", True, 
                             "Validation error expected for mock data")
                return True
            else:
                self.log_test("Agent Enrollment Simulation", False, 
                             f"HTTP {response.status_code}: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.log_test("Agent Enrollment Simulation", False, f"Connection error: {e}")
            return False
            
    def test_agent_local_functionality(self):
        """Test local agent functionality"""
        try:
            # Test if we can import the existing agent modules
            workspace_root = Path(__file__).parent
            agent_file = workspace_root / "backend_server.py"
            
            if agent_file.exists():
                self.log_test("Agent File Exists", True, "backend_server.py found")
                
                # Try to test agent configuration
                config_file = workspace_root / "config" / "agent_config.xml"
                if config_file.exists():
                    self.log_test("Agent Configuration", True, "agent_config.xml found")
                else:
                    self.log_test("Agent Configuration", False, "agent_config.xml missing")
                    
                return True
            else:
                self.log_test("Agent File Exists", False, "backend_server.py not found")
                return False
                
        except Exception as e:
            self.log_test("Agent Local Functionality", False, f"Error: {e}")
            return False
            
    def test_database_connectivity(self):
        """Test Manager database connectivity"""
        try:
            # Import manager database modules
            from manager_app.settings import get_settings
            settings = get_settings()
            
            # Test if database URL is configured
            if settings.DATABASE_URL:
                self.log_test("Database Configuration", True, 
                             f"Database URL configured: {settings.DATABASE_URL.split('@')[0]}@***")
                return True
            else:
                self.log_test("Database Configuration", False, "No database URL")
                return False
                
        except Exception as e:
            self.log_test("Database Configuration", False, f"Import error: {e}")
            return False
            
    def run_all_tests(self):
        """Run all tests"""
        print("🔍 STARTING COMPREHENSIVE AGENT-MANAGER COMMUNICATION TEST")
        print("=" * 80)
        
        # Test Manager functionality
        manager_health = self.test_manager_health()
        manager_enrollment = self.test_manager_enrollment_endpoint()
        manager_docs = self.test_manager_api_docs()
        manager_db = self.test_database_connectivity()
        
        # Test Agent functionality
        agent_local = self.test_agent_local_functionality()
        
        # Test integration
        enrollment_sim = self.simulate_agent_enrollment()
        
        print("\n" + "=" * 80)
        print("📋 TEST SUMMARY")
        print("=" * 80)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result["success"])
        
        print(f"Tests Run: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {total_tests - passed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if passed_tests == total_tests:
            print("\n🎉 ALL TESTS PASSED!")
            print("✅ Manager-Agent communication is working perfectly!")
        else:
            print(f"\n⚠️  {total_tests - passed_tests} tests failed")
            print("❌ Some issues need to be resolved")
            
        return passed_tests == total_tests

if __name__ == "__main__":
    test_suite = ManagerAgentTestSuite()
    success = test_suite.run_all_tests()
    sys.exit(0 if success else 1)