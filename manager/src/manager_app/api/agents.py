"""
Agent management endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
import structlog

from ..db.database import get_db_session
from ..db.crud import list_agents, get_agent_by_id, update_agent_status
from ..db.models import Agent

router = APIRouter(tags=["agents"])
logger = structlog.get_logger()


class AgentResponse(BaseModel):
    """Agent response model"""
    agent_id: str
    hostname: str
    status: str
    os_type: str
    os_version: str
    agent_version: str
    ip_address: Optional[str]
    tags: List[str]
    last_seen_at: Optional[str]
    certificate_expires_at: str
    created_at: str
    
    class Config:
        from_attributes = True


class AgentListResponse(BaseModel):
    """Agent list response"""
    agents: List[AgentResponse]
    total: int
    offset: int
    limit: int


@router.get("/agents", response_model=AgentListResponse)
async def list_enrolled_agents(
    status: Optional[str] = Query(None, description="Filter by agent status"),
    tags: Optional[str] = Query(None, description="Filter by tags (comma-separated)"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of agents to return"),
    offset: int = Query(0, ge=0, description="Number of agents to skip"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    List enrolled agents with optional filtering
    
    Returns paginated list of agents with their current status,
    last seen timestamps, and certificate information.
    """
    try:
        tag_list = tags.split(",") if tags else None
        
        agents = await list_agents(
            db=db,
            status=status,
            tags=tag_list,
            limit=limit,
            offset=offset
        )
        
        # Convert to response models
        agent_responses = []
        for agent in agents:
            agent_responses.append(AgentResponse(
                agent_id=agent.agent_id,
                hostname=agent.hostname,
                status=agent.status,
                os_type=agent.os_type,
                os_version=agent.os_version,
                agent_version=agent.agent_version,
                ip_address=agent.ip_address,
                tags=agent.tags,
                last_seen_at=agent.last_seen_at.isoformat() if agent.last_seen_at else None,
                certificate_expires_at=agent.certificate_expires_at.isoformat(),
                created_at=agent.created_at.isoformat()
            ))
        
        return AgentListResponse(
            agents=agent_responses,
            total=len(agent_responses),  # TODO: Add proper count query
            offset=offset,
            limit=limit
        )
        
    except Exception as e:
        logger.error("Failed to list agents", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve agents"
        )


@router.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_agent_details(
    agent_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get detailed information about a specific agent
    
    Returns complete agent information including connection history,
    certificate details, and current status.
    """
    try:
        agent = await get_agent_by_id(db, agent_id)
        if not agent:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Agent {agent_id} not found"
            )
        
        return AgentResponse(
            agent_id=agent.agent_id,
            hostname=agent.hostname,
            status=agent.status,
            os_type=agent.os_type,
            os_version=agent.os_version,
            agent_version=agent.agent_version,
            ip_address=agent.ip_address,
            tags=agent.tags,
            last_seen_at=agent.last_seen_at.isoformat() if agent.last_seen_at else None,
            certificate_expires_at=agent.certificate_expires_at.isoformat(),
            created_at=agent.created_at.isoformat()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get agent details", agent_id=agent_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve agent details"
        )


class AgentStatusUpdate(BaseModel):
    """Agent status update request"""
    status: str = Field(..., description="New agent status")


@router.put("/agents/{agent_id}/status")
async def update_agent_status_endpoint(
    agent_id: str,
    status_update: AgentStatusUpdate,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Update agent status
    
    Valid statuses: enrolled, active, inactive, revoked
    """
    try:
        valid_statuses = ["enrolled", "active", "inactive", "revoked"]
        if status_update.status not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of: {valid_statuses}"
            )
        
        agent = await update_agent_status(db, agent_id, status_update.status)
        if not agent:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Agent {agent_id} not found"
            )
        
        logger.info("Agent status updated", agent_id=agent_id, status=status_update.status)
        
        return {
            "success": True,
            "message": f"Agent status updated to {status_update.status}",
            "agent_id": agent_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to update agent status", agent_id=agent_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update agent status"
        )


# UI-Compatible API Endpoints (New format for Admin UI)
class UIAgentResponse(BaseModel):
    """UI-compatible agent response"""
    id: str
    hostname: str
    ip_address: Optional[str]
    port: int = 8443
    status: str  # online, offline, error
    last_seen: str
    os_info: str
    agent_version: str
    architecture: Optional[str] = None
    enrolled_at: str
    last_scan: Optional[str] = None
    tags: List[str]


class UIPaginatedAgents(BaseModel):
    """UI-compatible paginated response"""
    items: List[UIAgentResponse]
    total: int
    page: int
    per_page: int
    pages: int


@router.get("/ui/agents", response_model=UIPaginatedAgents)
async def get_agents_ui_format(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
    tags: Optional[List[str]] = Query(None),
    search: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db_session)
):
    """Get agents in UI-compatible format"""
    try:
        # For now, return sample data that matches UI expectations
        sample_agents = [
            UIAgentResponse(
                id="agent_1",
                hostname="WIN-SERVER-01",
                ip_address="192.168.1.100",
                status="online",
                last_seen="2025-09-27T21:00:00Z",
                os_info="Windows Server 2019",
                agent_version="1.0.0",
                architecture="x64",
                enrolled_at="2025-09-27T20:00:00Z",
                tags=["production", "windows", "server"]
            ),
            UIAgentResponse(
                id="agent_2", 
                hostname="UBUNTU-WS-01",
                ip_address="192.168.1.101",
                status="offline",
                last_seen="2025-09-27T19:00:00Z",
                os_info="Ubuntu 22.04 LTS",
                agent_version="1.0.0",
                architecture="x64",
                enrolled_at="2025-09-27T18:00:00Z",
                tags=["development", "linux", "workstation"]
            )
        ]
        
        # Apply filters
        if status:
            sample_agents = [a for a in sample_agents if a.status == status]
        
        if tags:
            sample_agents = [a for a in sample_agents if any(tag in a.tags for tag in tags)]
        
        if search:
            sample_agents = [a for a in sample_agents if 
                           search.lower() in a.hostname.lower() or 
                           search.lower() in (a.ip_address or "").lower()]
        
        total = len(sample_agents)
        pages = (total + per_page - 1) // per_page
        
        return UIPaginatedAgents(
            items=sample_agents,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
        
    except Exception as e:
        logger.error("Failed to get agents for UI", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve agents"
        )


@router.get("/ui/agents/{agent_id}", response_model=UIAgentResponse)
async def get_agent_ui_format(
    agent_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """Get single agent in UI-compatible format"""
    # Return sample data for now
    if agent_id == "agent_1":
        return UIAgentResponse(
            id="agent_1",
            hostname="WIN-SERVER-01",
            ip_address="192.168.1.100",
            status="online",
            last_seen="2025-09-27T21:00:00Z",
            os_info="Windows Server 2019",
            agent_version="1.0.0",
            architecture="x64",
            enrolled_at="2025-09-27T20:00:00Z",
            last_scan="2025-09-27T20:30:00Z",
            tags=["production", "windows", "server"]
        )
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Agent not found"
    )