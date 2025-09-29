"""
Command signing and verification for secure agent communication
"""

import json
import base64
import uuid
import hashlib
import hmac
from typing import Dict, Any, Optional
from datetime import datetime
import structlog

logger = structlog.get_logger()

# Fallback to HMAC if cryptography is not available
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("Cryptography library not available, using HMAC fallback")

# Development signing key
DEV_SIGNING_KEY = "RiskNoX_Dev_Signing_Key_2025"


class CommandSigner:
    """Digital signature manager for commands"""
    
    def __init__(self):
        self._private_key = None
        self._public_key = None
        if CRYPTO_AVAILABLE:
            self._load_signing_keys()
        else:
            logger.info("Using HMAC-based signing for development")
    
    def _load_signing_keys(self):
        """Load or generate signing keys"""
        try:
            # Generate ephemeral keys for development
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            self._public_key = self._private_key.public_key()
            logger.info("Generated ephemeral RSA signing keys for development")
                
        except Exception as e:
            logger.error("Failed to generate signing keys", error=str(e))
            self._private_key = None
            self._public_key = None
    
    def sign_command(self, command_payload: Dict[str, Any]) -> Optional[str]:
        """Sign command payload"""
        try:
            # Serialize command payload deterministically
            payload_json = json.dumps(command_payload, sort_keys=True, separators=(',', ':'))
            
            if CRYPTO_AVAILABLE and self._private_key:
                # Use RSA signing
                payload_bytes = payload_json.encode('utf-8')
                signature = self._private_key.sign(
                    payload_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return base64.b64encode(signature).decode('ascii')
            else:
                # Use HMAC fallback
                signature = hmac.new(
                    DEV_SIGNING_KEY.encode('utf-8'),
                    payload_json.encode('utf-8'),
                    hashlib.sha256
                ).hexdigest()
                return f"hmac:{signature}"
            
        except Exception as e:
            logger.error("Failed to sign command", error=str(e))
            return None
    
    def verify_command(self, command_payload: Dict[str, Any], signature: str) -> bool:
        """Verify command signature"""
        try:
            payload_json = json.dumps(command_payload, sort_keys=True, separators=(',', ':'))
            
            if signature.startswith("hmac:"):
                # Verify HMAC signature
                expected_signature = hmac.new(
                    DEV_SIGNING_KEY.encode('utf-8'),
                    payload_json.encode('utf-8'),
                    hashlib.sha256
                ).hexdigest()
                return hmac.compare_digest(signature[5:], expected_signature)
            
            elif CRYPTO_AVAILABLE and self._public_key:
                # Verify RSA signature
                signature_bytes = base64.b64decode(signature.encode('ascii'))
                payload_bytes = payload_json.encode('utf-8')
                
                self._public_key.verify(
                    signature_bytes,
                    payload_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True
            else:
                logger.warning("Cannot verify signature - no verification method available")
                return True  # Allow unsigned for development
            
        except Exception as e:
            logger.error("Command signature verification failed", error=str(e))
            return False
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format for agents"""
        if CRYPTO_AVAILABLE and self._public_key:
            public_key_pem = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return public_key_pem.decode('ascii')
        else:
            return f"HMAC_KEY:{DEV_SIGNING_KEY}"


# Global signer instance
_signer_instance: Optional[CommandSigner] = None


def get_signer() -> CommandSigner:
    """Get command signer instance (singleton)"""
    global _signer_instance
    if _signer_instance is None:
        _signer_instance = CommandSigner()
    return _signer_instance


def sign_command_payload(command_payload: Dict[str, Any]) -> Optional[str]:
    """Sign command payload using global signer"""
    signer = get_signer()
    return signer.sign_command(command_payload)


def verify_command_signature(command_payload: Dict[str, Any], signature: str) -> bool:
    """Verify command signature using global signer"""
    if not signature:
        return True  # Allow unsigned for development
    signer = get_signer()
    return signer.verify_command(command_payload, signature)


def get_public_key_for_agents() -> str:
    """Get public key PEM for agent verification"""
    signer = get_signer()
    return signer.get_public_key_pem()


def sign_message(message: Dict[str, Any]) -> Dict[str, Any]:
    """Sign a message and return signed message with signature"""
    # Add timestamp and message ID for freshness
    message_with_metadata = {
        **message,
        "timestamp": datetime.utcnow().isoformat(),
        "message_id": str(uuid.uuid4())
    }
    
    signature = sign_command_payload(message_with_metadata)
    
    return {
        "message": message_with_metadata,
        "signature": signature or "",
        "signed_by": "manager"
    }


def verify_message_signature(signed_message: Dict[str, Any]) -> bool:
    """Verify a signed message"""
    try:
        message = signed_message.get("message")
        signature = signed_message.get("signature")
        
        if not message:
            return False
        
        if not signature:
            return True  # Allow unsigned for development
            
        return verify_command_signature(message, signature)
        
    except Exception as e:
        logger.error("Message signature verification failed", error=str(e))
        return False