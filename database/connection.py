import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from database.models import Base
from dotenv import load_dotenv
import logging

load_dotenv()
logger = logging.getLogger(__name__)

# Use DATABASE_URL from .env, but fall back to local SQLite so the server
# starts instantly with zero external dependencies.
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

if not DATABASE_URL:
    DATABASE_URL = "sqlite+aiosqlite:///./firewall.db"
    logger.info("No DATABASE_URL set — using local SQLite (firewall.db)")

# aiosqlite is needed for SQLite async; asyncpg for Postgres
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    engine = create_async_engine(DATABASE_URL, echo=False, connect_args=connect_args)
else:
    engine = create_async_engine(DATABASE_URL, echo=False)

AsyncSessionLocal = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

async def init_db():
    """Create all tables on startup (safe to run multiple times)."""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database initialised successfully")
    except Exception as e:
        logger.error(f"Database init error: {e}")
        raise
