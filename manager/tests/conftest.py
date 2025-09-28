"""
Test configuration and fixtures
"""

import pytest
import asyncio
from typing import AsyncGenerator
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from manager_app.main import app
from manager_app.db.database import get_db_session, Base
from manager_app.settings import get_settings


# Test settings
class TestSettings:
    DATABASE_URL = "sqlite+aiosqlite:///:memory:"
    DEBUG = True
    REDIS_URL = "redis://localhost:6379/15"  # Test DB
    JWT_SECRET_KEY = "test_secret_key"


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def test_db():
    """Create test database"""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
        echo=True,
    )
    
    async_session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield async_session_factory
    
    # Drop tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def db_session(test_db) -> AsyncGenerator[AsyncSession, None]:
    """Get database session for tests"""
    async with test_db() as session:
        yield session


@pytest.fixture
def override_get_db_session(db_session):
    """Override database dependency for tests"""
    async def _get_db_session():
        yield db_session
    
    app.dependency_overrides[get_db_session] = _get_db_session
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client(override_get_db_session):
    """Test client with database override"""
    return TestClient(app)