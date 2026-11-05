import os
import asyncio
from pathlib import Path
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from backend.utils.logger import get_logger
from backend.database.exceptions import DatabaseConnectionError

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

logger = get_logger(__name__)

# Config values will be read inside connect_db() to ensure load_dotenv() has executed.

from typing import Optional

class DatabaseManager:
    """
    Async Singleton Connection Manager for MongoDB.
    """
    client: Optional[AsyncIOMotorClient] = None
    db = None

    @classmethod
    async def connect_db(cls, retries: int = 2, backoff_factor: float = 1.5):
        """
        Initializes connection pool with exponential backoff on failure.
        Designed to be called during FastAPI lifespan startup event.
        Falls back to resilient in-memory database store if cloud database is unreachable.
        """
        if cls.db is not None:
            return

        mongo_uri = os.getenv("MONGODB_URL", os.getenv("MONGO_URI", "mongodb://localhost:27017"))
        mongo_db_name = os.getenv("MONGO_DB", "netriq_db")
        min_pool_size = int(os.getenv("MONGO_MIN_POOL_SIZE", "10"))
        max_pool_size = int(os.getenv("MONGO_MAX_POOL_SIZE", "100"))
        timeout_ms = int(os.getenv("MONGO_TIMEOUT_MS", "4000"))

        delay = 1.0
        for attempt in range(1, retries + 1):
            try:
                logger.info(f"Attempting MongoDB connection to '{mongo_db_name}' (Attempt {attempt}/{retries})...")
                cls.client = AsyncIOMotorClient(
                    mongo_uri,
                    minPoolSize=min_pool_size,
                    maxPoolSize=max_pool_size,
                    serverSelectionTimeoutMS=timeout_ms,
                    connectTimeoutMS=timeout_ms,
                    socketTimeoutMS=10000
                )
                # Force a call to verify connection
                await cls.client.server_info()
                cls.db = cls.client[mongo_db_name]
                logger.info(f"Successfully connected to MongoDB database: {mongo_db_name}")
                await cls._ensure_indexes()
                return
            except (ConnectionFailure, ServerSelectionTimeoutError, Exception) as e:
                logger.warning(f"MongoDB connection attempt {attempt} failed: {e}")
                if cls.client is not None:
                    try:
                        cls.client.close()
                    except Exception:
                        pass
                    cls.client = None
                if attempt < retries:
                    logger.info(f"Retrying in {delay} seconds...")
                    await asyncio.sleep(delay)
                    delay *= backoff_factor
                else:
                    logger.warning(
                        "[DatabaseManager] Remote MongoDB unreachable (SSL/IP whitelist block). "
                        "Falling back to resilient In-Memory Database store so NetrIQ services and login remain fully functional."
                    )
                    from backend.database.in_memory_db import InMemoryDatabase
                    cls.db = InMemoryDatabase()
                    cls.client = None
                    return

    @classmethod
    async def close_db(cls):
        """Gracefully shuts down connection pool."""
        if cls.client is not None:
            cls.client.close()
            cls.client = None
        cls.db = None
        logger.info("MongoDB connection closed.")

    @classmethod
    def get_db(cls):
        """Returns the active database instance. Raises error if not connected."""
        if cls.db is None:
            from backend.database.in_memory_db import InMemoryDatabase
            cls.db = InMemoryDatabase()
        return cls.db

    @classmethod
    async def _ensure_indexes(cls):
        """Delegates to the authoritative index definitions in database/indexes.py."""
        from backend.database.indexes import ensure_indexes  # lazy to avoid circular import
        await ensure_indexes()

    @classmethod
    async def health_check(cls) -> bool:
        """Pings the database to verify connectivity for api/health.py."""
        if cls.db is not None:
            return True
        if cls.client is None:
            return False
        try:
            await cls.client.admin.command('ping')
            return True
        except Exception as e:
            logger.warning(f"Database health check failed: {e}")
            return False
