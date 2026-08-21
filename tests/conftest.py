"""Pytest fixtures for async testing with isolated database and test client."""

import os
from typing import AsyncGenerator
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.deps import get_db
from app.core.rate_limit import limiter
from app.core.rbac import Role
from app.core.security import hash_password
from app.db.base import Base
from app.main import app
from app.models.user import User

# Disable rate limiter during pytest execution
limiter.enabled = False

TEST_DB_FILE = "./test_secure_auth.db"
TEST_DATABASE_URL = f"sqlite+aiosqlite:///{TEST_DB_FILE}"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    future=True,
)

TestingSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@pytest_asyncio.fixture(autouse=True)
async def reset_db():
    """Drop and recreate all database tables for test isolation."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provide clean database session for each test."""
    async with TestingSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Async test HTTP client with database dependency override."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def regular_user(db_session: AsyncSession) -> User:
    """Fixture providing a standard active user."""
    user = User(
        email="regular.user@example.com",
        hashed_password=hash_password("Secur3P@ssw0rd!"),
        full_name="Regular User",
        role=Role.USER.value,
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def admin_user(db_session: AsyncSession) -> User:
    """Fixture providing an active administrator user."""
    user = User(
        email="admin.user@example.com",
        hashed_password=hash_password("AdminP@ssw0rd!"),
        full_name="Admin User",
        role=Role.ADMIN.value,
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user
