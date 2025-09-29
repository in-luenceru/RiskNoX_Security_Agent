"""
Database connection and session management
"""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
import structlog

from ..settings import get_settings

logger = structlog.get_logger()

# Database engine and session factory
engine = None
async_session_factory = None


class Base(DeclarativeBase):
    """SQLAlchemy declarative base"""
    pass


async def init_db():
    """Initialize database connection and create tables"""
    global engine, async_session_factory
    
    settings = get_settings()
    
    # Create async engine
    engine = create_async_engine(
        settings.DATABASE_URL,
        pool_size=settings.DATABASE_POOL_SIZE,
        max_overflow=20,
        pool_pre_ping=True,
        echo=settings.DATABASE_ECHO,
    )
    
    # Create session factory
    async_session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    # Create tables
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created/verified")
    except Exception as e:
        logger.warning("Failed to create database tables", error=str(e))
    
    logger.info("Database connection initialized", url=settings.DATABASE_URL.split('@')[1] if '@' in settings.DATABASE_URL else settings.DATABASE_URL)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get database session"""
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_async_db_session() -> AsyncSession:
    """Get async database session for Celery tasks"""
    if async_session_factory is None:
        await init_db()
    return async_session_factory()


async def get_async_db_session() -> AsyncSession:
    """Get async database session for Celery tasks"""
    if async_session_factory is None:
        await init_db()
    return async_session_factory()