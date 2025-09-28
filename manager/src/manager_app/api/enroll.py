"""
Agent enrollment endpoints for CSR processing and certificate issuance
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Form, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
import structlog

from ..db.database import get_db_session
from ..db.crud import create_agent, get_agent_by_hostname
from ..security.ca import generate_agent_certificate, validate_csr
from ..security.models import AgentMetadata

router = APIRouter(tags=["enrollment"])
logger = structlog.get_logger()


class EnrollmentRequest(BaseModel):
    """Agent enrollment request"""
    hostname: str = Field(..., min_length=1, max_length=255, description="Agent hostname")
    os_type: str = Field(..., description="Operating system type")
    os_version: str = Field(..., description="Operating system version")
    agent_version: str = Field(..., description="Agent software version")
    ip_address: Optional[str] = Field(None, description="Agent IP address")
    tags: Optional[str] = Field(None, description="Comma-separated tags")


class EnrollmentResponse(BaseModel):
    """Agent enrollment response"""
    success: bool
    agent_id: str
    certificate: str
    message: str
    expires_at: datetime


@router.post("/enroll", response_model=EnrollmentResponse)
async def enroll_agent(
    csr: UploadFile = File(..., description="Certificate Signing Request (PEM format)"),
    hostname: str = Form(..., description="Agent hostname"),
    os_type: str = Form(..., description="Operating system type"),
    os_version: str = Form(..., description="Operating system version"), 
    agent_version: str = Form(..., description="Agent software version"),
    ip_address: Optional[str] = Form(None, description="Agent IP address"),
    tags: Optional[str] = Form(None, description="Comma-separated tags"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Enroll a new agent with CSR-based certificate issuance
    
    Process:
    1. Validate CSR format and content
    2. Check if hostname is already enrolled
    3. Generate and sign X.509 certificate
    4. Store agent metadata in database
    5. Return signed certificate and agent ID
    
    Example usage:
    ```bash
    curl -X POST https://manager.example.com/api/v1/enroll \
         -F "csr=@agent.csr.pem" \
         -F "hostname=workstation-01" \
         -F "os_type=Windows" \
         -F "os_version=Windows 11 Pro" \
         -F "agent_version=1.0.0"
    ```
    """
    
    try:
        # Read CSR content
        csr_content = await csr.read()
        if not csr_content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="CSR file is empty"
            )
        
        csr_pem = csr_content.decode('utf-8')
        
        # Validate CSR format and extract information
        csr_info = validate_csr(csr_pem)
        if not csr_info:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid CSR format or content"
            )
        
        logger.info(
            "Processing agent enrollment",
            hostname=hostname,
            os_type=os_type,
            csr_subject=csr_info.get("subject"),
            csr_key_size=csr_info.get("key_size")
        )
        
        # Check if agent already exists
        existing_agent = await get_agent_by_hostname(db, hostname)
        if existing_agent:
            logger.warning("Agent enrollment rejected - hostname already exists", hostname=hostname)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Agent with hostname '{hostname}' is already enrolled"
            )
        
        # Generate agent ID
        agent_id = str(uuid.uuid4())
        
        # Create agent metadata
        metadata = AgentMetadata(
            agent_id=agent_id,
            hostname=hostname,
            os_type=os_type,
            os_version=os_version,
            agent_version=agent_version,
            ip_address=ip_address,
            tags=tags.split(",") if tags else []
        )
        
        # Generate and sign certificate
        certificate_data = generate_agent_certificate(
            agent_id=agent_id,
            hostname=hostname,
            csr_pem=csr_pem,
            metadata=metadata
        )
        
        if not certificate_data:
            logger.error("Failed to generate certificate", agent_id=agent_id, hostname=hostname)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate agent certificate"
            )
        
        # Store agent in database
        await create_agent(
            db=db,
            agent_id=agent_id,
            hostname=hostname,
            os_type=os_type,
            os_version=os_version,
            agent_version=agent_version,
            ip_address=ip_address,
            tags=tags.split(",") if tags else [],
            certificate_serial=certificate_data["serial_number"],
            certificate_fingerprint=certificate_data["fingerprint"],
            certificate_expires_at=certificate_data["expires_at"]
        )
        
        logger.info(
            "Agent enrolled successfully",
            agent_id=agent_id,
            hostname=hostname,
            certificate_serial=certificate_data["serial_number"],
            expires_at=certificate_data["expires_at"]
        )
        
        return EnrollmentResponse(
            success=True,
            agent_id=agent_id,
            certificate=certificate_data["certificate_pem"],
            message="Agent enrolled successfully",
            expires_at=certificate_data["expires_at"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Agent enrollment failed",
            hostname=hostname,
            error=str(e),
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during enrollment"
        )


@router.post("/enroll/validate-csr")
async def validate_csr_endpoint(csr: UploadFile = File(...)):
    """
    Validate CSR format and content without enrollment
    
    Useful for testing CSR generation before actual enrollment
    """
    try:
        csr_content = await csr.read()
        csr_pem = csr_content.decode('utf-8')
        
        csr_info = validate_csr(csr_pem)
        if not csr_info:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid CSR format"
            )
        
        return {
            "valid": True,
            "subject": csr_info["subject"],
            "key_size": csr_info["key_size"],
            "signature_algorithm": csr_info["signature_algorithm"],
            "public_key_type": csr_info["public_key_type"]
        }
        
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CSR must be in PEM text format"
        )
    except Exception as e:
        logger.error("CSR validation failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to validate CSR"
        )