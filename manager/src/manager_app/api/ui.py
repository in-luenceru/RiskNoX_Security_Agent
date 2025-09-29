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
            # Determine status based on WebSocket connection state and last_seen_at
            agent_status = "offline"  # default
            
            # Check WebSocket connection status first
            from ..ws.connection_manager import connection_manager
            is_ws_connected = agent.agent_id in connection_manager.agent_connections
            
            if is_ws_connected:
                agent_status = "online"
            elif agent.last_seen_at:
                last_seen = agent.last_seen_at
                if isinstance(last_seen, str):
                    last_seen = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                now = datetime.now(timezone.utc)
                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=timezone.utc)
                
                time_diff = (now - last_seen).total_seconds()
                # Agent is online if seen within last 2 minutes
                agent_status = "online" if time_diff < 120 else "offline"
            
            # Override with error status if agent has error status
            if agent.status in ["error", "failed", "revoked"]:
                agent_status = "error"
            
            # Apply search filter
            if search:
                search_lower = search.lower()
                if (search_lower not in agent.hostname.lower() and 
                    search_lower not in (agent.ip_address or "").lower() and
                    search_lower not in agent.agent_id.lower()):
                    continue
            
            # Apply status filter
            if status and agent_status != status:
                continue
            
            # Get last scan from agent metadata
            last_scan = None
            if agent.agent_metadata and agent.agent_metadata.get("last_scan"):
                last_scan = agent.agent_metadata["last_scan"]
            
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
                last_scan=last_scan,
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
        
        # Count online agents using WebSocket connection status
        from ..ws.connection_manager import connection_manager
        online_agents = len(connection_manager.agent_connections)
        
        # Count pending commands
        from sqlalchemy import select, func
        from ..db.models import Command
        pending_commands_query = select(func.count(Command.command_id)).where(
            Command.status.in_(["pending", "sent", "acknowledged"])
        )
        pending_commands_result = await db.execute(pending_commands_query)
        pending_commands = pending_commands_result.scalar() or 0
        
        # Count recent threats from scan results
        recent_threats_query = select(func.count(Command.command_id)).where(
            Command.command_type == "scan",
            Command.status == "completed",
            Command.result.op("->")("threats_found").astext.cast(Integer) > 0
        )
        try:
            from sqlalchemy import Integer
            recent_threats_result = await db.execute(recent_threats_query)
            recent_threats = recent_threats_result.scalar() or 0
        except:
            recent_threats = 0
        
        return {
            "total_agents": total_agents,
            "active_agents": online_agents,
            "pending_commands": pending_commands,
            "recent_threats": recent_threats,
            "system_health": "healthy" if online_agents > 0 else "warning"
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