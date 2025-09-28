"""
Certificate Authority (CA) operations for agent certificates
"""

import os
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import structlog

from ..settings import get_settings
from .models import CertificateInfo, AgentMetadata

logger = structlog.get_logger()


class CertificateAuthority:
    """Internal Certificate Authority for agent certificates"""
    
    def __init__(self):
        self.settings = get_settings()
        self._ca_private_key = None
        self._ca_certificate = None
        self._load_ca_credentials()
    
    def _load_ca_credentials(self):
        """Load CA private key and certificate"""
        try:
            if self.settings.CA_PRIVATE_KEY_PATH and self.settings.CA_CERTIFICATE_PATH:
                # Load from files
                with open(self.settings.CA_PRIVATE_KEY_PATH, 'rb') as f:
                    key_data = f.read()
                    password = self.settings.CA_KEY_PASSWORD.encode() if self.settings.CA_KEY_PASSWORD else None
                    self._ca_private_key = serialization.load_pem_private_key(key_data, password=password)
                
                with open(self.settings.CA_CERTIFICATE_PATH, 'rb') as f:
                    cert_data = f.read()
                    self._ca_certificate = x509.load_pem_x509_certificate(cert_data)
                
                logger.info("CA credentials loaded from files")
            else:
                # Generate self-signed CA for development
                self._generate_self_signed_ca()
                logger.warning("Using self-signed CA for development - not suitable for production")
                
        except Exception as e:
            logger.error("Failed to load CA credentials", error=str(e))
            raise RuntimeError("CA initialization failed") from e
    
    def _generate_self_signed_ca(self):
        """Generate self-signed CA for development"""
        # Generate CA private key
        self._ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        
        # Create CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Development"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "RiskNoX"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RiskNoX Security"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, "RiskNoX Development CA"),
        ])
        
        self._ca_certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self._ca_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)  # 10 years for CA
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).sign(self._ca_private_key, hashes.SHA256())
    
    def generate_agent_certificate(
        self,
        agent_id: str,
        hostname: str,
        csr_pem: str,
        metadata: AgentMetadata
    ) -> Optional[Dict[str, Any]]:
        """Generate and sign agent certificate from CSR"""
        try:
            # Parse CSR
            csr = x509.load_pem_x509_csr(csr_pem.encode())
            
            # Validate CSR signature
            if not csr.is_signature_valid:
                logger.error("Invalid CSR signature", agent_id=agent_id)
                return None
            
            # Build certificate
            certificate = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                self._ca_certificate.subject
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=self.settings.CERT_VALIDITY_DAYS)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(hostname),
                    x509.RFC822Name(f"{agent_id}@risknox.internal"),
                ]),
                critical=False,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            ).sign(self._ca_private_key, hashes.SHA256())
            
            # Generate certificate PEM
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
            
            # Calculate fingerprint
            fingerprint = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
            
            logger.info(
                "Agent certificate generated",
                agent_id=agent_id,
                hostname=hostname,
                serial=str(certificate.serial_number),
                expires_at=certificate.not_valid_after
            )
            
            return {
                "certificate_pem": cert_pem,
                "serial_number": str(certificate.serial_number),
                "fingerprint": fingerprint,
                "expires_at": certificate.not_valid_after,
                "subject": certificate.subject.rfc4514_string(),
            }
            
        except Exception as e:
            logger.error("Failed to generate agent certificate", agent_id=agent_id, error=str(e))
            return None
    
    def validate_agent_certificate(self, cert_pem: str) -> Optional[CertificateInfo]:
        """Validate agent certificate against CA"""
        try:
            certificate = x509.load_pem_x509_certificate(cert_pem.encode())
            
            # Verify certificate was signed by our CA
            self._ca_certificate.public_key().verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                certificate.signature_algorithm_oid._name
            )
            
            # Check expiration
            if datetime.utcnow() > certificate.not_valid_after:
                logger.warning("Certificate expired", serial=str(certificate.serial_number))
                return None
            
            fingerprint = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
            
            return CertificateInfo(
                subject=certificate.subject.rfc4514_string(),
                public_key_type=certificate.public_key().__class__.__name__,
                key_size=certificate.public_key().key_size if hasattr(certificate.public_key(), 'key_size') else None,
                signature_algorithm=certificate.signature_algorithm_oid._name,
                serial_number=str(certificate.serial_number),
                fingerprint=fingerprint,
                expires_at=certificate.not_valid_after
            )
            
        except Exception as e:
            logger.error("Certificate validation failed", error=str(e))
            return None


# Global CA instance
_ca_instance: Optional[CertificateAuthority] = None


def get_ca() -> CertificateAuthority:
    """Get Certificate Authority instance (singleton)"""
    global _ca_instance
    if _ca_instance is None:
        _ca_instance = CertificateAuthority()
    return _ca_instance


def validate_csr(csr_pem: str) -> Optional[Dict[str, Any]]:
    """Validate CSR format and extract information"""
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        
        if not csr.is_signature_valid:
            return None
        
        public_key = csr.public_key()
        key_size = public_key.key_size if hasattr(public_key, 'key_size') else None
        
        return {
            "subject": csr.subject.rfc4514_string(),
            "public_key_type": public_key.__class__.__name__,
            "key_size": key_size,
            "signature_algorithm": csr.signature_algorithm_oid._name,
        }
        
    except Exception as e:
        logger.error("CSR validation failed", error=str(e))
        return None


def generate_agent_certificate(
    agent_id: str,
    hostname: str,
    csr_pem: str,
    metadata: AgentMetadata
) -> Optional[Dict[str, Any]]:
    """Generate agent certificate using global CA instance"""
    ca = get_ca()
    return ca.generate_agent_certificate(agent_id, hostname, csr_pem, metadata)