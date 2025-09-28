"""
Certificate management for agent mTLS authentication
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import structlog

logger = structlog.get_logger()


class CertificateManager:
    """Manages agent certificates for mTLS authentication"""
    
    def __init__(self, cert_dir: str = "./certs"):
        self.cert_dir = Path(cert_dir)
        self.cert_dir.mkdir(exist_ok=True)
        
        self.cert_file = self.cert_dir / "agent.crt"
        self.key_file = self.cert_dir / "agent.key"
        self.agent_id_file = self.cert_dir / "agent_id.txt"
        
    def save_certificate(self, certificate_pem: str, private_key_pem: str):
        """Save certificate and private key to files"""
        try:
            # Save certificate
            with open(self.cert_file, 'w') as f:
                f.write(certificate_pem)
                
            # Save private key with restricted permissions
            with open(self.key_file, 'w') as f:
                f.write(private_key_pem)
                
            # Set restrictive permissions on private key
            if os.name != 'nt':  # Unix-like systems
                os.chmod(self.key_file, 0o600)
                
            logger.info("Certificate and key saved", cert_file=str(self.cert_file))
            
        except Exception as e:
            logger.error("Failed to save certificate", error=str(e))
            raise
            
    def has_valid_certificate(self) -> bool:
        """Check if we have a valid, non-expired certificate"""
        try:
            if not (self.cert_file.exists() and self.key_file.exists()):
                return False
                
            # Load and validate certificate
            with open(self.cert_file, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
                
            # Check expiration
            now = datetime.utcnow()
            if cert.not_valid_after < now:
                logger.warning("Certificate is expired")
                return False
                
            if cert.not_valid_before > now:
                logger.warning("Certificate is not yet valid")
                return False
                
            logger.info("Valid certificate found", 
                       expires=cert.not_valid_after.isoformat())
            return True
            
        except Exception as e:
            logger.error("Certificate validation failed", error=str(e))
            return False
            
    def get_certificate_paths(self) -> Tuple[Optional[str], Optional[str]]:
        """Get paths to certificate and key files"""
        if self.has_valid_certificate():
            return str(self.cert_file), str(self.key_file)
        return None, None
        
    def get_certificate_serial(self) -> Optional[str]:
        """Get certificate serial number"""
        try:
            if not self.cert_file.exists():
                return None
                
            with open(self.cert_file, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
                
            return format(cert.serial_number, 'x')
            
        except Exception as e:
            logger.error("Failed to get certificate serial", error=str(e))
            return None
            
    def get_certificate_info(self) -> Optional[dict]:
        """Get certificate information"""
        try:
            if not self.cert_file.exists():
                return None
                
            with open(self.cert_file, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
                
            return {
                "serial": format(cert.serial_number, 'x'),
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_valid_before": cert.not_valid_before.isoformat(),
                "not_valid_after": cert.not_valid_after.isoformat(),
                "is_valid": cert.not_valid_before <= datetime.utcnow() <= cert.not_valid_after
            }
            
        except Exception as e:
            logger.error("Failed to get certificate info", error=str(e))
            return None
            
    def save_agent_id(self, agent_id: str):
        """Save agent ID to file"""
        try:
            with open(self.agent_id_file, 'w') as f:
                f.write(agent_id)
            logger.info("Agent ID saved", agent_id=agent_id)
        except Exception as e:
            logger.error("Failed to save agent ID", error=str(e))
            
    def get_agent_id(self) -> Optional[str]:
        """Get saved agent ID"""
        try:
            if self.agent_id_file.exists():
                with open(self.agent_id_file, 'r') as f:
                    return f.read().strip()
        except Exception as e:
            logger.error("Failed to read agent ID", error=str(e))
        return None
        
    def cleanup_certificates(self):
        """Remove all certificate files"""
        try:
            for file_path in [self.cert_file, self.key_file, self.agent_id_file]:
                if file_path.exists():
                    file_path.unlink()
                    
            logger.info("Certificate files cleaned up")
            
        except Exception as e:
            logger.error("Failed to cleanup certificates", error=str(e))