"""
Agent enrollment module for CSR generation and Manager enrollment
"""

import json
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Tuple
import tempfile

import aiohttp
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import structlog

logger = structlog.get_logger()


class AgentEnrollment:
    """Handles agent enrollment with Manager via CSR exchange"""
    
    def __init__(self, manager_base_url: str):
        self.manager_url = manager_base_url.rstrip("/")
        self.enroll_endpoint = f"{self.manager_url}/api/v1/enroll"
        
    def generate_csr(self, hostname: str, **kwargs) -> Tuple[str, str]:
        """
        Generate Certificate Signing Request (CSR) and private key
        
        Returns:
            Tuple of (csr_pem, private_key_pem)
        """
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Create subject name
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RiskNoX Agent"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])
            
            # Create CSR
            csr = x509.CertificateSigningRequestBuilder().subject_name(
                subject
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(hostname),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Serialize to PEM
            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            logger.info("CSR generated successfully", hostname=hostname)
            return csr_pem, private_key_pem
            
        except Exception as e:
            logger.error("CSR generation failed", error=str(e))
            raise
            
    async def enroll(self, hostname: str, os_type: str, os_version: str, 
                    agent_version: str, ip_address: str = None, 
                    tags: list = None) -> Dict[str, Any]:
        """
        Enroll agent with Manager using CSR
        
        Returns:
            Dict with enrollment result including certificate and agent_id
        """
        try:
            # Generate CSR and private key
            csr_pem, private_key_pem = self.generate_csr(hostname)
            
            # Prepare enrollment data
            form_data = aiohttp.FormData()
            
            # Add CSR as file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as csr_file:
                csr_file.write(csr_pem)
                csr_file.flush()
                
                with open(csr_file.name, 'rb') as f:
                    form_data.add_field('csr', f, filename='agent.csr', 
                                      content_type='application/x-pem-file')
                    
                    # Add metadata
                    form_data.add_field('hostname', hostname)
                    form_data.add_field('os_type', os_type)
                    form_data.add_field('os_version', os_version)
                    form_data.add_field('agent_version', agent_version)
                    
                    if ip_address:
                        form_data.add_field('ip_address', ip_address)
                        
                    if tags:
                        form_data.add_field('tags', ','.join(tags))
                    
                    # Send enrollment request
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            self.enroll_endpoint,
                            data=form_data,
                            timeout=aiohttp.ClientTimeout(total=30)
                        ) as response:
                            
                            response_data = await response.json()
                            
                            if response.status == 200 and response_data.get("success"):
                                logger.info("Enrollment successful", 
                                           agent_id=response_data.get("agent_id"))
                                
                                return {
                                    "success": True,
                                    "agent_id": response_data["agent_id"],
                                    "certificate": response_data["certificate"],
                                    "private_key": private_key_pem,
                                    "expires_at": response_data.get("expires_at"),
                                    "message": response_data.get("message")
                                }
                            else:
                                error_msg = response_data.get("message", "Enrollment failed")
                                logger.error("Enrollment failed", 
                                           status=response.status, 
                                           error=error_msg)
                                
                                return {
                                    "success": False,
                                    "error": error_msg,
                                    "status_code": response.status
                                }
                                
            # Cleanup temp file
            Path(csr_file.name).unlink(missing_ok=True)
            
        except aiohttp.ClientError as e:
            logger.error("Network error during enrollment", error=str(e))
            return {
                "success": False,
                "error": f"Network error: {str(e)}"
            }
        except Exception as e:
            logger.error("Enrollment failed", error=str(e))
            return {
                "success": False,
                "error": str(e)
            }
            
    async def check_enrollment_status(self, agent_id: str) -> Dict[str, Any]:
        """Check agent enrollment status with Manager"""
        try:
            status_url = f"{self.manager_url}/api/v1/agents/{agent_id}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    status_url,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    
                    if response.status == 200:
                        agent_data = await response.json()
                        return {
                            "success": True,
                            "agent": agent_data
                        }
                    else:
                        return {
                            "success": False,
                            "error": f"Agent not found or error: {response.status}"
                        }
                        
        except Exception as e:
            logger.error("Status check failed", agent_id=agent_id, error=str(e))
            return {
                "success": False,
                "error": str(e)
            }
            
    def validate_certificate(self, certificate_pem: str) -> bool:
        """Validate received certificate"""
        try:
            cert = x509.load_pem_x509_certificate(certificate_pem.encode('utf-8'))
            
            # Check if certificate is not expired
            now = datetime.utcnow()
            if cert.not_valid_after < now:
                logger.error("Certificate is expired")
                return False
                
            if cert.not_valid_before > now:
                logger.error("Certificate is not yet valid")
                return False
                
            logger.info("Certificate validation successful", 
                       subject=cert.subject.rfc4514_string(),
                       expires=cert.not_valid_after.isoformat())
            return True
            
        except Exception as e:
            logger.error("Certificate validation failed", error=str(e))
            return False


async def main():
    """Main CLI entry point for agent enrollment"""
    import argparse
    import socket
    import platform
    import sys
    import os
    
    parser = argparse.ArgumentParser(description="RiskNoX Agent Enrollment")
    parser.add_argument("--manager-url", required=True, help="Manager URL (e.g., http://192.168.1.100:8001)")
    parser.add_argument("--agent-name", help="Agent name (defaults to hostname)")
    parser.add_argument("--config-dir", default="config", help="Configuration directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    # Setup logging
    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)
    
    # Get system information
    hostname = args.agent_name or socket.gethostname()
    os_type = platform.system()
    os_version = platform.release()
    agent_version = "1.0.0"
    
    try:
        # Get IP address
        ip_address = socket.gethostbyname(socket.gethostname())
    except:
        ip_address = None
    
    print(f"🔐 Starting enrollment for agent: {hostname}")
    print(f"📡 Manager URL: {args.manager_url}")
    print(f"💻 OS: {os_type} {os_version}")
    
    # Initialize enrollment
    enrollment = AgentEnrollment(args.manager_url)
    
    try:
        # Perform enrollment
        result = await enrollment.enroll_agent(
            hostname=hostname,
            os_type=os_type,
            os_version=os_version,
            agent_version=agent_version,
            ip_address=ip_address
        )
        
        if result["success"]:
            print("✅ Enrollment successful!")
            print(f"🆔 Agent ID: {result['agent_id']}")
            
            # Save configuration and certificates
            config_dir = Path(args.config_dir)
            config_dir.mkdir(exist_ok=True)
            
            # Save agent info
            agent_info = {
                "agent_id": result["agent_id"],
                "agent_name": hostname,
                "manager_url": args.manager_url,
                "enrolled": True,
                "enrolled_at": datetime.now().isoformat(),
                "expires_at": result.get("expires_at")
            }
            
            with open(config_dir / "agent_info.json", "w") as f:
                json.dump(agent_info, f, indent=2)
            
            # Save certificate and private key
            with open(config_dir / "agent.crt", "w") as f:
                f.write(result["certificate"])
                
            with open(config_dir / "agent.key", "w") as f:
                f.write(result["private_key"])
                
            print(f"📁 Configuration saved to {config_dir}")
            print(f"🔑 Certificate expires: {result.get('expires_at', 'Unknown')}")
            
            # Verify certificate
            if enrollment.validate_certificate(result["certificate"]):
                print("✅ Certificate validation successful")
            else:
                print("⚠️ Certificate validation failed")
                
        else:
            print("❌ Enrollment failed!")
            print(f"Error: {result.get('error', 'Unknown error')}")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Enrollment error: {e}")
        logger.error("Enrollment process failed", error=str(e))
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())