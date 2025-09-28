"""
Events API endpoints
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from ..db.database import get_db_session

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
    # Placeholder implementation with sample data
    sample_events = [
        EventResponse(
            id="event_1",
            level="info",
            source="agent",
            event_type="agent_connected",
            message="Agent connected successfully",
            timestamp=datetime.utcnow(),
            created_at=datetime.utcnow(),
            agent_id="agent_123"
        ),
        EventResponse(
            id="event_2", 
            level="success",
            source="scanner",
            event_type="scan_completed",
            message="Quick scan completed successfully",
            timestamp=datetime.utcnow(),
            created_at=datetime.utcnow(),
            agent_id="agent_123",
            scan_id="scan_456"
        ),
        EventResponse(
            id="event_3",
            level="warning",
            source="patch_system",
            event_type="patch_failed",
            message="Patch installation failed",
            details={"patch_id": "KB123456", "error": "Access denied"},
            timestamp=datetime.utcnow(),
            created_at=datetime.utcnow(),
            agent_id="agent_123"
        )
    ]
    
    # Filter by level if provided
    if level:
        sample_events = [e for e in sample_events if e.level == level]
    
    # Filter by source if provided
    if source:
        sample_events = [e for e in sample_events if e.source == source]
    
    # Simple search in message if provided
    if search:
        sample_events = [e for e in sample_events if search.lower() in e.message.lower()]
    
    return PaginatedEvents(
        items=sample_events,
        total=len(sample_events),
        page=page,
        per_page=per_page,
        pages=1
    )