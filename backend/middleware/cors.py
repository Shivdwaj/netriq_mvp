from fastapi.middleware.cors import CORSMiddleware
import os
from typing import List

DEFAULT_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
]

ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

ALLOWED_HEADERS = [
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "X-Sensor-Key",
    "X-Sensor-ID",
    "X-Tenant-ID",
    "Accept",
    "Origin",
]

EXPOSED_HEADERS = ["Content-Length", "X-Correlation-ID"]


def get_allowed_origins() -> List[str]:
    """Parses and sanitizes ALLOWED_ORIGINS from environment, falling back to safe local origins."""
    raw = os.getenv("ALLOWED_ORIGINS", "").strip()
    if not raw:
        return list(DEFAULT_ALLOWED_ORIGINS)

    origins = [o.strip() for o in raw.split(",") if o.strip()]
    # Wildcard origin with credentials violates CORS specifications and is a security hazard.
    # Filter wildcard if present and fallback to default trusted origins.
    filtered = [o for o in origins if o != "*"]
    return filtered if filtered else list(DEFAULT_ALLOWED_ORIGINS)


def add_cors_middleware(app):
    """
    Configures strict, explicit CORS policies without wildcard regex origins.
    Enforces explicit origin validation, restricted HTTP methods, and safe headers.
    """
    trusted_origins = get_allowed_origins()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=trusted_origins,
        allow_credentials=True,
        allow_methods=ALLOWED_METHODS,
        allow_headers=ALLOWED_HEADERS,
        expose_headers=EXPOSED_HEADERS,
        max_age=600,
    )
