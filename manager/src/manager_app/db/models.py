"""
SQLAlchemy database models
"""

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import String, DateTime, Boolean, Integer, Text, JSON, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from .database import Base


class Agent(Base):
    """Agent model for enrolled security agents"""
    __tablename__ = "agents"

    # Primary fields
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, nullable=False) 
    status: Mapped[str] = mapped_column(String(20), default="enrolled")  # enrolled, active, inactive, revoked
    
    # System information
    os_type: Mapped[str] = mapped_column(String(50), nullable=False)
    os_version: Mapped[str] = mapped_column(String(100), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(20), nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))  # IPv4/IPv6
    tags: Mapped[List[str]] = mapped_column(JSONB, default=list)
    
    # Certificate information
    certificate_serial: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    certificate_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    certificate_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    
    # Connection tracking
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    connection_count: Mapped[int] = mapped_column(Integer, default=0)
    
    # Metadata
    agent_metadata: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    commands: Mapped[List["Command"]] = relationship("Command", back_populates="agent")
    events: Mapped[List["Event"]] = relationship("Event", back_populates="agent")
    
    # Indexes
    __table_args__ = (
        Index("idx_agents_hostname", "hostname"),
        Index("idx_agents_status", "status"),
        Index("idx_agents_last_seen", "last_seen_at"),
        Index("idx_agents_cert_serial", "certificate_serial"),
    )

    def __repr__(self):
        return f"<Agent(agent_id='{self.agent_id}', hostname='{self.hostname}', status='{self.status}')>"


class Command(Base):
    """Commands sent to agents"""
    __tablename__ = "commands"

    # Primary fields
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    command_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False)
    
    # Command details
    command_type: Mapped[str] = mapped_column(String(50), nullable=False)  # scan, patch, config, etc.
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)  # Digital signature
    
    # Status tracking
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, sent, ack, completed, failed, expired
    priority: Mapped[int] = mapped_column(Integer, default=5)  # 1=highest, 10=lowest
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    max_retries: Mapped[int] = mapped_column(Integer, default=3)
    
    # Timing
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    ack_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    
    # Results
    result: Mapped[Optional[dict]] = mapped_column(JSONB)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    
    # Metadata
    created_by: Mapped[str] = mapped_column(String(50), nullable=False)  # admin user or system
    command_metadata: Mapped[dict] = mapped_column(JSONB, default=dict)
    
    # Relationships
    agent: Mapped["Agent"] = relationship("Agent", back_populates="commands")
    
    # Indexes
    __table_args__ = (
        Index("idx_commands_agent_id", "agent_id"),
        Index("idx_commands_status", "status"),
        Index("idx_commands_type", "command_type"),
        Index("idx_commands_created", "created_at"),
        Index("idx_commands_expires", "expires_at"),
    )

    def __repr__(self):
        return f"<Command(command_id='{self.command_id}', type='{self.command_type}', status='{self.status}')>"


class Event(Base):
    """Agent events and audit log"""
    __tablename__ = "events"

    # Primary fields
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id"))
    
    # Event details
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)  # connection, scan_result, error, etc.
    event_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    severity: Mapped[str] = mapped_column(String(10), default="info")  # debug, info, warning, error, critical
    
    # Context
    source: Mapped[str] = mapped_column(String(50), nullable=False)  # agent, manager, admin
    user_id: Mapped[Optional[str]] = mapped_column(String(50))
    session_id: Mapped[Optional[str]] = mapped_column(String(36))
    
    # Timing
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    agent: Mapped[Optional["Agent"]] = relationship("Agent", back_populates="events")
    
    # Indexes
    __table_args__ = (
        Index("idx_events_agent_id", "agent_id"),
        Index("idx_events_type", "event_type"),
        Index("idx_events_timestamp", "timestamp"),
        Index("idx_events_severity", "severity"),
    )

    def __repr__(self):
        return f"<Event(type='{self.event_type}', severity='{self.severity}', timestamp='{self.timestamp}')>"


class Schedule(Base):
    """Scheduled tasks and jobs"""
    __tablename__ = "schedules"

    # Primary fields
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    
    # Schedule configuration
    schedule_type: Mapped[str] = mapped_column(String(20), nullable=False)  # cron, interval, once
    schedule_config: Mapped[dict] = mapped_column(JSONB, nullable=False)  # cron expression, interval seconds, etc.
    
    # Task configuration
    task_type: Mapped[str] = mapped_column(String(50), nullable=False)  # scan, patch, config
    task_config: Mapped[dict] = mapped_column(JSONB, nullable=False)
    
    # Targeting
    target_tags: Mapped[List[str]] = mapped_column(JSONB, default=list)  # Target agents by tags
    target_agents: Mapped[List[str]] = mapped_column(JSONB, default=list)  # Specific agent IDs
    
    # Status
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    run_count: Mapped[int] = mapped_column(Integer, default=0)
    
    # Metadata
    created_by: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Indexes
    __table_args__ = (
        Index("idx_schedules_enabled", "enabled"),
        Index("idx_schedules_next_run", "next_run_at"),
        Index("idx_schedules_type", "task_type"),
    )

    def __repr__(self):
        return f"<Schedule(name='{self.name}', type='{self.task_type}', enabled={self.enabled})>"


class Patch(Base):
    """Patch artifacts and rollout tracking"""
    __tablename__ = "patches"

    # Primary fields
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    
    # Artifact information
    artifact_url: Mapped[str] = mapped_column(String(500), nullable=False)  # S3 URL
    artifact_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA256
    artifact_signature: Mapped[str] = mapped_column(Text, nullable=False)  # GPG signature
    artifact_size: Mapped[int] = mapped_column(Integer, nullable=False)
    
    # Rollout configuration
    rollout_strategy: Mapped[str] = mapped_column(String(20), default="manual")  # manual, canary, blue_green
    rollout_config: Mapped[dict] = mapped_column(JSONB, default=dict)
    
    # Status tracking
    status: Mapped[str] = mapped_column(String(20), default="draft")  # draft, testing, rolling_out, deployed, failed, rolled_back
    target_tags: Mapped[List[str]] = mapped_column(JSONB, default=list)
    
    # Statistics
    total_agents: Mapped[int] = mapped_column(Integer, default=0)
    success_count: Mapped[int] = mapped_column(Integer, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    rollback_count: Mapped[int] = mapped_column(Integer, default=0)
    
    # Metadata
    created_by: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Indexes
    __table_args__ = (
        Index("idx_patches_status", "status"),
        Index("idx_patches_version", "version"),
        Index("idx_patches_created", "created_at"),
    )

    def __repr__(self):
        return f"<Patch(name='{self.name}', version='{self.version}', status='{self.status}')>"