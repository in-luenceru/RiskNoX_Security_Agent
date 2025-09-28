"""
Command signing and verification for secure agent communication
"""

import json
import base64
import uuid
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import structlog

from ..settings import get_settings

logger = structlog.get_logger()


class CommandSigner:
    """Digital signature manager for commands"""
    
    def __init__(self):
        self.settings = get_settings()
        self._private_key = None
        self._public_key = None
        self._load_signing_keys()
    
    def _load_signing_keys(self):
        """Load or generate signing keys"""
        try:
            # In production, load from secure key storage (Vault, HSM, etc.)
            # For development, generate ephemeral keys
            if hasattr(self.settings, 'SIGNING_PRIVATE_KEY_PATH'):
                # Load from file
                with open(self.settings.SIGNING_PRIVATE_KEY_PATH, 'rb') as f:
                    key_data = f.read()
                    self._private_key = serialization.load_pem_private_key(key_data, password=None)
                    self._public_key = self._private_key.public_key()
                logger.info("Signing keys loaded from file")
            else:
                # Generate ephemeral keys for development
                self._private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                )
                self._public_key = self._private_key.public_key()
                logger.warning("Using ephemeral signing keys - not suitable for production")
                
        except Exception as e:
            logger.error("Failed to load signing keys", error=str(e))
            raise RuntimeError("Signing key initialization failed") from e
    
    def sign_command(self, command_payload: Dict[str, Any]) -> Optional[str]:
        """Sign command payload with private key"""
        try:
            # Serialize command payload deterministically
            payload_json = json.dumps(command_payload, sort_keys=True, separators=(',', ':'))
            payload_bytes = payload_json.encode('utf-8')
            
            # Sign with RSA-PSS
            signature = self._private_key.sign(
                payload_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Return base64-encoded signature
            return base64.b64encode(signature).decode('ascii')
            
        except Exception as e:
            logger.error("Failed to sign command", error=str(e))
            return None
    
    def verify_command(self, command_payload: Dict[str, Any], signature: str) -> bool:
        """Verify command signature with public key"""
        try:
            # Deserialize signature
            signature_bytes = base64.b64decode(signature.encode('ascii'))
            
            # Serialize payload the same way as signing
            payload_json = json.dumps(command_payload, sort_keys=True, separators=(',', ':'))
            payload_bytes = payload_json.encode('utf-8')
            
            # Verify signature
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
            
        except Exception as e:
            logger.error("Command signature verification failed", error=str(e))
            return False
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format for agents"""
        public_key_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key_pem.decode('ascii')


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
    signer = get_signer()
    return signer.verify_command(command_payload, signature)


def get_public_key_for_agents() -> str:
    """Get public key PEM for agent verification"""
    signer = get_signer()
    return signer.get_public_key_pem()


def sign_message(message: Dict[str, Any]) -> Dict[str, Any]:
    """Sign a message and return signed message with signature"""
    from datetime import datetime
    
    # Add timestamp and message ID for freshness
    message_with_metadata = {
        **message,
        "timestamp": datetime.utcnow().isoformat(),
        "message_id": str(uuid.uuid4()) if 'uuid' in globals() else "dev_msg_id"
    }
    
    signature = sign_command_payload(message_with_metadata)
    
    return {
        "message": message_with_metadata,
        "signature": signature,
        "signed_by": "manager"
    }


def verify_message_signature(signed_message: Dict[str, Any]) -> bool:
    """Verify a signed message"""
    try:
        message = signed_message.get("message")
        signature = signed_message.get("signature")
        
        if not message or not signature:
            return False
            
        return verify_command_signature(message, signature)
        
    except Exception as e:
        logger.error("Message signature verification failed", error=str(e))
        return False