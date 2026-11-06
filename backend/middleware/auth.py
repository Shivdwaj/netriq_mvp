import hashlib
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from backend.auth.jwt_handler import verify_token
from backend.auth.exceptions import TokenExpiredError, InvalidTokenError
from backend.utils.logger import get_logger

logger = get_logger(__name__)

class AuthMiddleware(BaseHTTPMiddleware):
    """
    HTTP Interceptor for JWT and Sensor Token authentication.
    - No Authorization header → request.state.user = None (anonymous; protected routes
      reject it via the permissions dependency).
    - Valid Bearer token → decoded payload or authenticated sensor metadata.
    - X-Sensor-Key header → authenticated sensor metadata.
    - Malformed / expired / tampered token → immediate HTTP 401 with WWW-Authenticate
      header (RFC 6750 §3.1) so the client knows to re-authenticate, not retry.
    """
    # Paths that must never be blocked even without a token
    _PUBLIC_PREFIXES = (
        "/api/v1/auth/login",
        "/api/v1/auth/refresh",
        "/docs",
        "/openapi",
        "/redoc",
        "/api/v1/sensors/register"
    )

    async def dispatch(self, request: Request, call_next):
        # Paths that never require token validation (login, refresh, docs, health, sensor register)
        path = request.url.path
        if any(path.startswith(prefix) for prefix in self._PUBLIC_PREFIXES) or path in ("/health", "/api/v1/health"):
            request.state.user = None
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        x_sensor_key = request.headers.get("X-Sensor-Key")

        if not auth_header and x_sensor_key:
            # Check sensor authentication via X-Sensor-Key header
            try:
                from backend.database.collections import sensors_repo
                key_hash = hashlib.sha256(x_sensor_key.encode("utf-8")).hexdigest()
                sensors = await sensors_repo.list(filter_query={"api_key_hash": key_hash}, limit=1)
                if sensors:
                    s = sensors[0]
                    request.state.user = {
                        "sub": s["sensor_id"],
                        "sensor_id": s["sensor_id"],
                        "username": s.get("name", "sensor"),
                        "role": "sensor",
                        "tenant_id": s.get("tenant_id", "default"),
                        "software_type": s.get("software_type", "sensor")
                    }
                    return await call_next(request)
            except Exception as e:
                logger.warning(f"Error checking X-Sensor-Key: {e}")

        if not auth_header:
            # Anonymous request — let protected routes enforce auth via dependencies
            request.state.user = None
            return await call_next(request)

        if not auth_header.startswith("Bearer "):
            # Malformed Authorization header
            return JSONResponse(
                status_code=401,
                headers={"WWW-Authenticate": "Bearer error=\"invalid_request\""},
                content={"error": "InvalidTokenError", "message": "Authorization header must use Bearer scheme."}
            )

        token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return JSONResponse(
                status_code=401,
                headers={"WWW-Authenticate": "Bearer error=\"invalid_request\""},
                content={"error": "InvalidTokenError", "message": "Bearer token is empty."}
            )

        try:
            payload = verify_token(token, expected_type="access")
            request.state.user = payload
        except TokenExpiredError:
            return JSONResponse(
                status_code=401,
                headers={"WWW-Authenticate": "Bearer error=\"invalid_token\", error_description=\"Token has expired\""},
                content={"error": "TokenExpiredError", "message": "Access token has expired. Please refresh your token."}
            )
        except InvalidTokenError as e:
            # Check if this Bearer token is a software sensor API key
            try:
                from backend.database.collections import sensors_repo
                key_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
                sensors = await sensors_repo.list(filter_query={"api_key_hash": key_hash}, limit=1)
                if sensors:
                    s = sensors[0]
                    request.state.user = {
                        "sub": s["sensor_id"],
                        "sensor_id": s["sensor_id"],
                        "username": s.get("name", "sensor"),
                        "role": "sensor",
                        "tenant_id": s.get("tenant_id", "default"),
                        "software_type": s.get("software_type", "sensor")
                    }
                    return await call_next(request)
            except Exception as se:
                logger.warning(f"Error checking sensor bearer key: {se}")

            return JSONResponse(
                status_code=401,
                headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""},
                content={"error": "InvalidTokenError", "message": str(e)}
            )

        return await call_next(request)
