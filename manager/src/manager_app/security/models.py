"""
Security models and data structures
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class AgentMetadata(BaseModel):
    """Agent metadata for certificate generation"""
    agent_id: str = Field(..., description="Unique agent identifier")
    hostname: str = Field(..., description="Agent hostname")
    os_type: str = Field(..., description="Operating system type")
    os_version: str = Field(..., description="Operating system version")
    agent_version: str = Field(..., description="Agent software version")
    ip_address: Optional[str] = Field(None, description="Agent IP address")
    tags: List[str] = Field(default_factory=list, description="Agent tags")


class CertificateInfo(BaseModel):
    """Certificate information extracted from CSR or certificate"""
    subject: str = Field(..., description="Certificate subject DN")
    public_key_type: str = Field(..., description="Public key type (RSA, ECDSA, etc.)")
    key_size: Optional[int] = Field(None, description="Key size in bits")
    signature_algorithm: str = Field(..., description="Signature algorithm")
    serial_number: Optional[str] = Field(None, description="Certificate serial number")
    fingerprint: Optional[str] = Field(None, description="Certificate fingerprint")
    expires_at: Optional[datetime] = Field(None, description="Certificate expiration")


class CommandPayload(BaseModel):
    """Base command payload structure"""
    command_id: str = Field(..., description="Unique command identifier")
    command_type: str = Field(..., description="Command type")
    issued_at: datetime = Field(..., description="Command issue timestamp")
    expires_at: datetime = Field(..., description="Command expiration timestamp")
    issued_by: str = Field(..., description="Command issuer")
    signature: str = Field(..., description="Command digital signature")
    payload: Dict[str, Any] = Field(..., description="Command-specific payload")


class ScanCommand(BaseModel):
    """Scan command payload"""
    scan_type: str = Field(..., description="Scan type: quick, full, directory")
    target_path: Optional[str] = Field(None, description="Directory path for directory scans")
    deep_scan: bool = Field(default=False, description="Enable deep scanning")
    quarantine: bool = Field(default=True, description="Quarantine threats")


class PatchCommand(BaseModel):
    """Patch installation command payload"""
    patch_id: str = Field(..., description="Patch identifier")
    artifact_url: str = Field(..., description="Patch artifact URL")
    artifact_hash: str = Field(..., description="Expected artifact hash")
    artifact_signature: str = Field(..., description="Artifact signature")
    install_options: Dict[str, Any] = Field(default_factory=dict, description="Installation options")


class ConfigCommand(BaseModel):
    """Configuration update command payload"""
    config_type: str = Field(..., description="Configuration type")
    config_data: Dict[str, Any] = Field(..., description="Configuration data")
    merge_mode: str = Field(default="replace", description="Configuration merge mode")


class WebBlockCommand(BaseModel):
    """Web blocking command payload"""
    action: str = Field(..., description="Action: block, unblock, list")
    urls: List[str] = Field(default_factory=list, description="URLs to block/unblock")
    categories: List[str] = Field(default_factory=list, description="URL categories")
    policy_id: Optional[str] = Field(None, description="Web blocking policy ID")