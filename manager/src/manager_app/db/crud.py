"""
Database CRUD operations
"""

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from sqlalchemy.orm import selectinload
import structlog

from .models import Agent, Command, Event, Schedule, Patch

logger = structlog.get_logger()


# Agent CRUD operations
async def create_agent(
    db: AsyncSession,
    agent_id: str,
    hostname: str,
    os_type: str,
    os_version: str,
    agent_version: str,
    certificate_serial: str,
    certificate_fingerprint: str,
    certificate_expires_at: datetime,
    ip_address: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> Agent:
    """Create a new agent"""
    agent = Agent(
        agent_id=agent_id,
        hostname=hostname,
        os_type=os_type,
        os_version=os_version,
        agent_version=agent_version,
        ip_address=ip_address,
        tags=tags or [],
        certificate_serial=certificate_serial,
        certificate_fingerprint=certificate_fingerprint,
        certificate_expires_at=certificate_expires_at,
        status="enrolled"
    )
    
    db.add(agent)
    await db.commit()
    await db.refresh(agent)
    
    logger.info("Agent created", agent_id=agent_id, hostname=hostname)
    return agent


async def get_agent_by_id(db: AsyncSession, agent_id: str) -> Optional[Agent]:
    """Get agent by agent_id"""
    result = await db.execute(
        select(Agent).where(Agent.agent_id == agent_id)
    )
    return result.scalar_one_or_none()


async def get_agent_by_hostname(db: AsyncSession, hostname: str) -> Optional[Agent]:
    """Get agent by hostname"""
    result = await db.execute(
        select(Agent).where(Agent.hostname == hostname)
    )
    return result.scalar_one_or_none()


async def get_agent_by_certificate_serial(db: AsyncSession, serial: str) -> Optional[Agent]:
    """Get agent by certificate serial number"""
    result = await db.execute(
        select(Agent).where(Agent.certificate_serial == serial)
    )
    return result.scalar_one_or_none()


async def list_agents(
    db: AsyncSession,
    status: Optional[str] = None,
    tags: Optional[List[str]] = None,
    limit: int = 100,
    offset: int = 0
) -> List[Agent]:
    """List agents with optional filtering"""
    query = select(Agent)
    
    if status:
        query = query.where(Agent.status == status)
    
    if tags:
        # Filter agents that have any of the specified tags
        for tag in tags:
            query = query.where(Agent.tags.op('@>')([tag]))
    
    query = query.offset(offset).limit(limit).order_by(Agent.created_at.desc())
    
    result = await db.execute(query)
    return result.scalars().all()


async def update_agent_last_seen(
    db: AsyncSession,
    agent_id: str,
    ip_address: Optional[str] = None
) -> Optional[Agent]:
    """Update agent last seen timestamp"""
    update_data = {"last_seen_at": datetime.utcnow()}
    if ip_address:
        update_data["last_ip_address"] = ip_address
    
    await db.execute(
        update(Agent)
        .where(Agent.agent_id == agent_id)
        .values(**update_data)
    )
    await db.commit()
    
    return await get_agent_by_id(db, agent_id)


async def update_agent_status(
    db: AsyncSession,
    agent_id: str,
    status: str
) -> Optional[Agent]:
    """Update agent status"""
    await db.execute(
        update(Agent)
        .where(Agent.agent_id == agent_id)
        .values(status=status, updated_at=datetime.utcnow())
    )
    await db.commit()
    
    return await get_agent_by_id(db, agent_id)


# Command CRUD operations
async def create_command(
    db: AsyncSession,
    agent_id: str,
    command_type: str,
    payload: dict,
    signature: str,
    created_by: str,
    expires_at: datetime,
    priority: int = 5
) -> Command:
    """Create a new command"""
    # Get agent UUID from agent_id
    agent = await get_agent_by_id(db, agent_id)
    if not agent:
        raise ValueError(f"Agent {agent_id} not found")
    
    command = Command(
        command_id=str(uuid.uuid4()),
        agent_id=agent.id,
        command_type=command_type,
        payload=payload,
        signature=signature,
        created_by=created_by,
        expires_at=expires_at,
        priority=priority,
        status="pending"
    )
    
    db.add(command)
    await db.commit()
    await db.refresh(command)
    
    logger.info("Command created", command_id=command.command_id, agent_id=agent_id, type=command_type)
    return command


async def get_command_by_id(db: AsyncSession, command_id: str) -> Optional[Command]:
    """Get command by ID with agent relationship"""
    result = await db.execute(
        select(Command)
        .options(selectinload(Command.agent))
        .where(Command.command_id == command_id)
    )
    return result.scalar_one_or_none()


async def get_pending_commands_for_agent(db: AsyncSession, agent_id: str) -> List[Command]:
    """Get pending commands for an agent"""
    agent = await get_agent_by_id(db, agent_id)
    if not agent:
        return []
    
    result = await db.execute(
        select(Command)
        .where(Command.agent_id == agent.id)
        .where(Command.status == "pending")
        .where(Command.expires_at > datetime.utcnow())
        .order_by(Command.priority.asc(), Command.created_at.asc())
    )
    return result.scalars().all()


async def update_command_status(
    db: AsyncSession,
    command_id: str,
    status: str,
    result: Optional[dict] = None,
    error_message: Optional[str] = None
) -> Optional[Command]:
    """Update command status and results"""
    update_data = {"status": status}
    
    if status == "sent":
        update_data["sent_at"] = datetime.utcnow()
    elif status == "ack":
        update_data["ack_at"] = datetime.utcnow()
    elif status in ["completed", "failed"]:
        update_data["completed_at"] = datetime.utcnow()
        if result:
            update_data["result"] = result
        if error_message:
            update_data["error_message"] = error_message
    
    await db.execute(
        update(Command)
        .where(Command.command_id == command_id)
        .values(**update_data)
    )
    await db.commit()
    
    return await get_command_by_id(db, command_id)


# Event CRUD operations  
async def create_event(
    db: AsyncSession,
    event_type: str,
    event_data: dict,
    source: str,
    agent_id: Optional[str] = None,
    user_id: Optional[str] = None,
    session_id: Optional[str] = None,
    severity: str = "info"
) -> Event:
    """Create a new event"""
    agent_uuid = None
    if agent_id:
        agent = await get_agent_by_id(db, agent_id)
        if agent:
            agent_uuid = agent.id
    
    event = Event(
        agent_id=agent_uuid,
        event_type=event_type,
        event_data=event_data,
        source=source,
        user_id=user_id,
        session_id=session_id,
        severity=severity
    )
    
    db.add(event)
    await db.commit()
    await db.refresh(event)
    
    logger.info("Event created", event_type=event_type, agent_id=agent_id, severity=severity)
    return event


async def list_events(
    db: AsyncSession,
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[Event]:
    """List events with optional filtering"""
    query = select(Event).options(selectinload(Event.agent))
    
    if agent_id:
        agent = await get_agent_by_id(db, agent_id)
        if agent:
            query = query.where(Event.agent_id == agent.id)
    
    if event_type:
        query = query.where(Event.event_type == event_type)
    
    if severity:
        query = query.where(Event.severity == severity)
    
    query = query.offset(offset).limit(limit).order_by(Event.timestamp.desc())
    
    result = await db.execute(query)
    return result.scalars().all()


# Additional CRUD operations for WebSocket functionality
async def get_agent_by_certificate_serial(db: AsyncSession, serial: str) -> Optional[Agent]:
    """Get agent by certificate serial number"""
    query = select(Agent).where(Agent.certificate_serial == serial)
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def update_agent_connection_status(
    db: AsyncSession, 
    agent_id: str, 
    status: str, 
    last_seen_at: Optional[datetime] = None
) -> bool:
    """Update agent connection status and last seen timestamp"""
    try:
        agent = await get_agent_by_id(db, agent_id)
        if not agent:
            return False
            
        agent.status = status
        if last_seen_at:
            agent.last_seen_at = last_seen_at
            
        await db.commit()
        return True
    except Exception as e:
        logger.error("Failed to update agent connection status", 
                    agent_id=agent_id, error=str(e))
        await db.rollback()
        return False


async def update_agent_metadata(
    db: AsyncSession, 
    agent_id: str, 
    metadata: dict
) -> bool:
    """Update agent metadata"""
    try:
        agent = await get_agent_by_id(db, agent_id)
        if not agent:
            return False
            
        # Merge with existing metadata
        if agent.agent_metadata:
            agent.agent_metadata.update(metadata)
        else:
            agent.agent_metadata = metadata
            
        await db.commit()
        return True
    except Exception as e:
        logger.error("Failed to update agent metadata", 
                    agent_id=agent_id, error=str(e))
        await db.rollback()
        return False


async def update_command_result(
    db: AsyncSession,
    command_id: str,
    status: str,
    result: Optional[dict] = None,
    error_message: Optional[str] = None
) -> bool:
    """Update command execution result"""
    try:
        query = select(Command).where(Command.command_id == command_id)
        db_result = await db.execute(query)
        command = db_result.scalar_one_or_none()
        
        if not command:
            logger.warning("Command not found for result update", command_id=command_id)
            return False
            
        command.status = status
        command.completed_at = datetime.utcnow()
        
        if result:
            command.result = result
            
        if error_message:
            command.error_message = error_message
            
        await db.commit()
        logger.info("Command result updated", command_id=command_id, status=status)
        return True
        
    except Exception as e:
        logger.error("Failed to update command result", 
                    command_id=command_id, error=str(e))
        await db.rollback()
        return False


async def create_event(db: AsyncSession, event_data: dict) -> Event:
    """Create event from dict data"""
    agent_id = event_data.get("agent_id")
    agent = await get_agent_by_id(db, agent_id) if agent_id else None
    
    event = Event(
        agent_id=agent.id if agent else None,
        event_type=event_data.get("event_type", "unknown"),
        event_data=event_data.get("event_data", {}),
        severity=event_data.get("severity", "info"),
        timestamp=event_data.get("timestamp", datetime.utcnow())
    )
    
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event