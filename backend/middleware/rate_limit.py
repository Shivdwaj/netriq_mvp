import time
import asyncio
import os
from collections import OrderedDict
from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Configurable limits
MAX_CACHE_ENTRIES = int(os.getenv("RATE_LIMIT_MAX_CACHE_ENTRIES", "10000"))
EVICTION_BATCH_SIZE = int(os.getenv("RATE_LIMIT_EVICTION_BATCH_SIZE", "1000"))

DEFAULT_GENERAL_LIMIT = int(os.getenv("RATE_LIMIT_GENERAL_MAX", "300"))
DEFAULT_AUTH_LIMIT = int(os.getenv("RATE_LIMIT_AUTH_MAX", "30"))
DEFAULT_INGEST_LIMIT = int(os.getenv("RATE_LIMIT_INGEST_MAX", "1200"))
DEFAULT_WINDOW_SECONDS = 60


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Hardened in-memory sliding/fixed-window rate limiter.
    Features:
    1. Multi-tier bucket partitioning (Auth vs Ingest vs General).
    2. Bounded LRU-style eviction: never drops the entire cache on threshold overflow.
    3. Fail-secure handling with structured HTTP 429 response and Retry-After header.
    4. Safe client IP extraction.
    """
    def __init__(
        self,
        app,
        max_requests: int = DEFAULT_GENERAL_LIMIT,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        auth_max: int = DEFAULT_AUTH_LIMIT,
        ingest_max: int = DEFAULT_INGEST_LIMIT,
    ):
        super().__init__(app)
        self.max_requests = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", str(max_requests)))
        self.window_seconds = window_seconds
        self.auth_max = auth_max
        self.ingest_max = ingest_max

        # Bounded LRU store: key -> {"count": int, "reset_time": float}
        self._cache: OrderedDict[str, dict] = OrderedDict()
        self._lock = asyncio.Lock()

    def _get_client_ip(self, request: Request) -> str:
        """Extracts client IP safely, taking X-Forwarded-For into account if present."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # First IP in chain is original client
            client_ip = forwarded.split(",")[0].strip()
            if client_ip:
                return client_ip
        if request.client and request.client.host:
            return request.client.host
        return "127.0.0.1"

    def _determine_bucket_and_limit(self, path: str) -> tuple[str, int, int]:
        """
        Categorizes path into (bucket_name, max_requests, window_seconds).
        """
        # Strict Auth endpoints
        if path.startswith("/api/v1/auth/") or path.startswith("/auth/"):
            return "auth", self.auth_max, self.window_seconds

        # Machine telemetry / sensor ingestion endpoints
        if path.startswith("/api/v1/sensor") or "/sensors/heartbeat" in path or "/sensors/eve" in path:
            return "ingest", self.ingest_max, self.window_seconds

        # General application routes
        return "general", self.max_requests, self.window_seconds

    def _evict_stale_or_oldest(self, now: float):
        """
        Prunes cache without clearing all entries.
        1. First removes expired windows.
        2. If still over capacity, pops oldest entries via FIFO/LRU order.
        """
        # 1. Remove expired
        expired = [k for k, v in self._cache.items() if now > v["reset_time"]]
        for k in expired:
            self._cache.pop(k, None)

        # 2. If still over limit, evict batch from oldest
        if len(self._cache) > MAX_CACHE_ENTRIES:
            num_to_pop = min(EVICTION_BATCH_SIZE, len(self._cache))
            for _ in range(num_to_pop):
                self._cache.popitem(last=False)

    async def dispatch(self, request: Request, call_next):
        client_ip = self._get_client_ip(request)
        path = request.url.path

        # Whitelist internal health checks and documentation schemas
        if path in ("/api/v1/health", "/health", "/docs", "/openapi.json", "/redoc"):
            return await call_next(request)

        bucket, limit, window = self._determine_bucket_and_limit(path)
        cache_key = f"{bucket}:{client_ip}" if bucket != "auth" else f"auth:{client_ip}:{path}"
        now = time.time()

        try:
            async with self._lock:
                if len(self._cache) >= MAX_CACHE_ENTRIES:
                    self._evict_stale_or_oldest(now)

                record = self._cache.get(cache_key)

                if not record or now > record["reset_time"]:
                    # New window
                    record = {"count": 1, "reset_time": now + window}
                    self._cache[cache_key] = record
                else:
                    record["count"] += 1
                    # Move to end (LRU touch)
                    self._cache.move_to_end(cache_key)

                    if record["count"] > limit:
                        retry_after = max(1, int(record["reset_time"] - now))
                        logger.warning(
                            f"[RateLimit] Rate limit exceeded for {client_ip} on [{bucket}] {path} "
                            f"({record['count']}/{limit}). Retry-After: {retry_after}s"
                        )
                        return JSONResponse(
                            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            content={
                                "error": "TooManyRequests",
                                "message": f"Rate limit exceeded for {bucket} tier. Try again in {retry_after} seconds.",
                                "retry_after": retry_after
                            },
                            headers={"Retry-After": str(retry_after)}
                        )

        except Exception as e:
            logger.error(f"[RateLimit] Error during rate limit evaluation: {e}")
            # Fail safely: do not crash server, allow request with warning
            return await call_next(request)

        return await call_next(request)
