"""
UI-specific API endpoints for the admin interface
"""

from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
import structlog

from ..db.database import get_db_session
from ..db.crud import list_agents, get_agent_by_id
from ..db.models import Agent

router = APIRouter(prefix="/ui", tags=["ui"])
logger = structlog.get_logger()


class AgentUI(BaseModel):
    """Agent model for UI"""
    id: str
    hostname: str
    ip_address: Optional[str]
    os_info: str
    agent_version: str
    status: str  # online, offline, error
    last_seen: str
    tags: List[str] = []
    certificate_status: str = "valid"  # valid, expired, revoked
    agent_metadata: dict = {}
    created_at: str
    updated_at: str
    architecture: Optional[str] = None
    enrolled_at: Optional[str] = None
    last_scan: Optional[str] = None

    class Config:
        from_attributes = True


class CommandUI(BaseModel):
    """Command model for UI"""
    id: str
    agent_id: str
    command_type: str  # scan, patch, config, custom
    command_data: dict
    status: str  # pending, sent, acknowledged, running, completed, failed, expired
    priority: str = "medium"  # low, medium, high, urgent
    created_by: str
    created_at: str
    sent_at: Optional[str] = None
    completed_at: Optional[str] = None
    response_data: Optional[dict] = None
    signature: Optional[str] = None
    progress: Optional[int] = None
    result: Optional[str] = None

    class Config:
        from_attributes = True


class PaginatedResponse(BaseModel):
    """Paginated response for UI"""
    items: List[AgentUI]
    total: int
    page: int
    per_page: int
    pages: int


@router.get("/agents", response_model=PaginatedResponse)
async def get_agents_ui(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(10, ge=1, le=100, description="Items per page"),
    status: Optional[str] = Query(None, description="Filter by status"),
    tags: Optional[List[str]] = Query(None, description="Filter by tags"),
    search: Optional[str] = Query(None, description="Search query"),
    db: AsyncSession = Depends(get_db_session)
):
    """Get agents with UI-friendly format and pagination"""
    try:
        offset = (page - 1) * per_page
        
        # Get total count first (without pagination)
        from sqlalchemy import select, func
        from ..db.models import Agent as DBAgent
        
        count_query = select(func.count(DBAgent.agent_id))
        if status:
            count_query = count_query.where(DBAgent.status == status)
        
        total_result = await db.execute(count_query)
        total = total_result.scalar() or 0
        
        # Get agents from database with pagination
        agents_data = await list_agents(
            db=db,
            limit=per_page,
            offset=offset,
            status=status
        )
        
        # Transform to UI format
        agents = []
        for agent in agents_data:
            # Determine status based on last_seen_at and current status
            agent_status = "offline"  # default
            if agent.status == "enrolled":
                if agent.last_seen_at:
                    last_seen = agent.last_seen_at
                    if isinstance(last_seen, str):
                        last_seen = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                    now = datetime.now(timezone.utc)
                    if last_seen.tzinfo is None:
                        last_seen = last_seen.replace(tzinfo=timezone.utc)
                    
                    time_diff = (now - last_seen).total_seconds()
                    agent_status = "online" if time_diff < 300 else "offline"  # 5 minutes
                else:
                    agent_status = "offline"
            elif agent.status in ["active", "connected"]:
                agent_status = "online"
            elif agent.status in ["error", "failed"]:
                agent_status = "error"
            
            agent_ui = AgentUI(
                id=agent.agent_id,
                hostname=agent.hostname,
                ip_address=agent.ip_address or "Unknown",
                os_info=f"{agent.os_type} {agent.os_version}",
                agent_version=agent.agent_version,
                status=agent_status,
                last_seen=agent.last_seen_at.isoformat() if agent.last_seen_at else "",
                tags=agent.tags or [],
                created_at=agent.created_at.isoformat(),
                updated_at=agent.created_at.isoformat(),
                enrolled_at=agent.created_at.isoformat(),
                certificate_status="valid" if agent.certificate_expires_at and agent.certificate_expires_at > datetime.now(timezone.utc) else "expired"
            )
            agents.append(agent_ui)
        
        pages = (total + per_page - 1) // per_page
        
        return PaginatedResponse(
            items=agents,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
        
    except Exception as e:
        logger.error("Failed to get agents for UI", error=str(e))
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve agents"
        )


@router.get("/agents/{agent_id}", response_model=AgentUI)
async def get_agent_ui(
    agent_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """Get single agent with UI-friendly format"""
    try:
        agent = await get_agent_by_id(db=db, agent_id=agent_id)
        if not agent:
            raise HTTPException(
                status_code=404,
                detail="Agent not found"
            )
        
        return AgentUI(
            id=agent.agent_id,
            hostname=agent.hostname,
            ip_address=agent.ip_address,
            os_info=f"{agent.os_type} {agent.os_version}",
            agent_version=agent.agent_version,
            status="online" if agent.status == "active" else "offline",
            last_seen=agent.last_seen_at.isoformat() if agent.last_seen_at else "",
            tags=agent.tags or [],
            created_at=agent.created_at.isoformat(),
            updated_at=agent.created_at.isoformat(),
            enrolled_at=agent.created_at.isoformat(),
            certificate_status="valid" if agent.certificate_expires_at else "expired"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get agent for UI", agent_id=agent_id, error=str(e))
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve agent"
        )


@router.get("/agents/{agent_id}/commands", response_model=dict)
async def get_agent_commands_ui(
    agent_id: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    db: AsyncSession = Depends(get_db_session)
):
    """Get agent commands with UI-friendly format"""
    # For now, return empty results since we need to implement command tracking
    return {
        "items": [],
        "total": 0,
        "page": page,
        "per_page": per_page,
        "pages": 0
    }


@router.get("/agents/{agent_id}/patches", response_model=dict)
async def get_agent_patches_ui(
    agent_id: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    db: AsyncSession = Depends(get_db_session)
):
    """Get agent patches with UI-friendly format"""
    # For now, return empty results since we need to implement patch tracking
    return {
        "items": [],
        "total": 0,
        "page": page,
        "per_page": per_page,
        "pages": 0
    }


@router.get("/system/stats", response_model=dict)
async def get_system_stats_ui(db: AsyncSession = Depends(get_db_session)):
    """Get system statistics for UI dashboard"""
    try:
        # Get basic stats
        agents_data = await list_agents(db=db, limit=1000, offset=0)  # Returns list directly
        total_agents = len(agents_data)
        
        # Count active agents (enrolled and active agents should be considered active)
        active_agents = len([a for a in agents_data if a.status in ["active", "enrolled"]])
        
        return {
            "total_agents": total_agents,
            "active_agents": active_agents,
            "pending_commands": 0,  # TODO: Implement command counting
            "recent_threats": 0,    # TODO: Implement threat counting
            "system_health": "healthy"
        }
        
    except Exception as e:
        logger.error("Failed to get system stats", error=str(e))
        return {
            "total_agents": 0,
            "active_agents": 0,
            "pending_commands": 0,
            "recent_threats": 0,
            "system_health": "unknown"
        }