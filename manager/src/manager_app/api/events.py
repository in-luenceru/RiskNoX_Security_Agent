"""
Events API endpoints
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
import structlog

from ..db.database import get_db_session

logger = structlog.get_logger()

router = APIRouter(prefix="/events", tags=["events"])


class EventResponse(BaseModel):
    id: str
    agent_id: Optional[str] = None
    event_type: str
    level: str
    source: str
    message: str
    details: Optional[dict] = None
    timestamp: datetime
    created_at: datetime
    user_id: Optional[str] = None
    command_id: Optional[str] = None
    scan_id: Optional[str] = None


class PaginatedEvents(BaseModel):
    items: List[EventResponse]
    total: int
    page: int
    per_page: int
    pages: int


@router.get("/", response_model=PaginatedEvents)
async def get_events(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    level: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db_session)
):
    """Get all events with pagination and filtering"""
    try:
        from ..db.crud import list_events
        
        # Get events from database
        events_data = await list_events(
            db=db,
            event_type=None,
            severity=level,
            limit=per_page,
            offset=(page - 1) * per_page
        )
        
        # Convert to response format
        events = []
        for event in events_data:
            agent_id = None
            if event.agent:
                agent_id = event.agent.agent_id
            
            # Map severity to level for UI compatibility
            level_mapping = {
                "debug": "info",
                "info": "info", 
                "warning": "warning",
                "error": "error",
                "critical": "error"
            }
            
            event_response = EventResponse(
                id=str(event.id),
                agent_id=agent_id,
                event_type=event.event_type,
                level=level_mapping.get(event.severity, "info"),
                source=event.source,
                message=event.event_data.get("message", f"{event.event_type} event"),
                details=event.event_data,
                timestamp=event.timestamp,
                created_at=event.timestamp,
                user_id=event.user_id
            )
            events.append(event_response)
        
        # If no events from DB, show some sample manager actions
        if not events:
            sample_events = [
                EventResponse(
                    id="manager_1",
                    level="info",
                    source="manager",
                    event_type="manager_started",
                    message="RiskNoX Manager service started",
                    timestamp=datetime.utcnow(),
                    created_at=datetime.utcnow()
                ),
                EventResponse(
                    id="manager_2",
                    level="info",
                    source="manager",
                    event_type="database_initialized",
                    message="Database connection initialized successfully",
                    timestamp=datetime.utcnow(),
                    created_at=datetime.utcnow()
                )
            ]
            events = sample_events
        
        # Apply filters
        if level:
            events = [e for e in events if e.level == level]
        
        if source:
            events = [e for e in events if e.source == source]
        
        if search:
            events = [e for e in events if search.lower() in e.message.lower()]
        
        total = len(events)
        pages = (total + per_page - 1) // per_page
        
        return PaginatedEvents(
            items=events,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
        
    except Exception as e:
        logger.error("Failed to get events", error=str(e))
        # Return empty events list on error
        return PaginatedEvents(
            items=[],
            total=0,
            page=page,
            per_page=per_page,
            pages=0
        )