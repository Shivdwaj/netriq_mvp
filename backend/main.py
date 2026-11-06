from dotenv import load_dotenv
from pathlib import Path
load_dotenv(Path(__file__).parent / ".env")  # Always load backend/.env regardless of CWD

# NETRIQ Main Entrypoint (Real ML models & WebSockets active - Updated live pipeline)
import os
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.exceptions import RequestValidationError
from backend.utils.exceptions import NetriqException
from backend.utils.logger import get_logger
from backend.database.database import DatabaseManager
from backend.response.response_engine import ResponseEngine

# Import Middlewares
from backend.middleware.logging import LoggingMiddleware
from backend.middleware.cors import add_cors_middleware
from backend.middleware.security import SecurityHeadersMiddleware
from backend.middleware.auth import AuthMiddleware
from backend.middleware.rate_limit import RateLimitMiddleware

# Import Routers
from backend.api.auth import router as auth_router
from backend.api.dashboard import router as dashboard_router
from backend.api.analytics import router as analytics_router
from backend.api.monitoring import router as monitoring_router
from backend.api.prediction import router as prediction_router
from backend.api.incidents import router as incidents_router
from backend.api.history import router as history_router
from backend.api.reports import router as reports_router
from backend.api.response import router as response_router
from backend.api.users import router as users_router
from backend.api.settings import router as settings_router
from backend.api.health import router as health_router
from backend.api.behaviors import router as behaviors_router
from backend.api.telemetry import router as telemetry_router
from backend.api.sensor_ingest import router as sensor_ingest_router
from backend.api.events import router as events_router
from backend.api.threats import router as threats_router
from backend.api.management import router as management_router
from backend.api.rules import router as rules_router
from backend.api.websocket import router as websocket_router, websocket_endpoint

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle manager."""
    # --- STARTUP ---
    logger.info("Starting NETRIQ API...")
    await DatabaseManager.connect_db()
    logger.info("Database connected.")
    from backend.services.settings_service import settings_service
    await settings_service.load_persisted_settings()
    from backend.auth.auth_service import AuthService
    await AuthService().seed_initial_users()
    app.state.response_engine = ResponseEngine()  # init AFTER DB is ready

    # Engage Layer 4 Correlation Engine on EventBus
    try:
        from backend.pipeline import event_bus
        from backend.services.correlation_service import correlation_engine
        event_bus.subscribe(correlation_engine.process_event)
        logger.info("[Startup] Layer 4 Security Intelligence Correlator subscribed to EventBus.")
    except Exception as corr_err:
        logger.warning(f"[Startup] Could not subscribe correlation engine: {corr_err}")

    # Auto-engage live hardware packet monitoring on Npcap physical NIC (skip during automated test runs)
    if not os.environ.get("TESTING") and not os.environ.get("PYTEST_CURRENT_TEST"):
        try:
            from backend.services.monitoring_service import monitoring_service
            from backend.auth.roles import Role
            await monitoring_service.start(Role.ADMIN)
            logger.info("[Startup] Live hardware packet monitoring pipeline engaged on physical NIC.")
        except Exception as e:
            logger.warning(f"[Startup] Could not auto-engage live monitor: {e}")

    yield
    # --- SHUTDOWN ---
    logger.info("Shutting down NETRIQ API...")
    try:
        from backend.services.monitoring_service import monitoring_service
        from backend.auth.roles import Role
        await monitoring_service.stop(Role.ADMIN)
    except Exception:
        pass
    await DatabaseManager.close_db()
    await app.state.response_engine.close()
    logger.info("Cleanup complete.")


app = FastAPI(title="NETRIQ API", version="1.0.0", lifespan=lifespan)

# --- Middlewares ---
# Starlette executes middleware in reverse order of addition.
# Sequence below ensures execution order: RateLimit -> Auth -> SecurityHeaders -> CORS -> Logging
app.add_middleware(LoggingMiddleware)
add_cors_middleware(app)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AuthMiddleware)
app.add_middleware(RateLimitMiddleware)

# --- Exception Handlers ---
@app.exception_handler(NetriqException)
async def netriq_exception_handler(request: Request, exc: NetriqException):
    logger.error(f"Domain Error: {exc.__class__.__name__}: {str(exc)}")
    status_code = 400
    if exc.__class__.__name__ in ["InvalidCredentialsError", "TokenExpiredError", "InvalidTokenError"]:
        status_code = 401
    elif exc.__class__.__name__ in ["AccountLockedError", "InsufficientPermissionError"]:
        status_code = 403
    return JSONResponse(
        status_code=status_code,
        content={"error": exc.__class__.__name__, "message": str(exc), "detail": {}}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled Server Error: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "InternalServerError", "message": "An unexpected error occurred.", "detail": str(exc)}
    )

# --- Routers ---
@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs")

app.include_router(auth_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")
app.include_router(analytics_router, prefix="/api/v1")
app.include_router(monitoring_router, prefix="/api/v1")
app.include_router(prediction_router, prefix="/api/v1")
app.include_router(incidents_router, prefix="/api/v1")
app.include_router(history_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")
app.include_router(response_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")
app.include_router(settings_router, prefix="/api/v1")
app.include_router(health_router, prefix="/api/v1")
app.include_router(behaviors_router, prefix="/api/v1")
app.include_router(telemetry_router, prefix="/api/v1")
app.include_router(sensor_ingest_router, prefix="/api/v1")
app.include_router(events_router, prefix="/api/v1")
app.include_router(threats_router, prefix="/api/v1")
app.include_router(management_router, prefix="/api/v1")
app.include_router(rules_router, prefix="/api/v1")
app.include_router(health_router)  # Also expose root /health for docker/lb health checks
app.include_router(websocket_router)  # WebSockets sit at root /ws
app.websocket("/ws")(websocket_endpoint)
app.websocket("/api/v1/ws")(websocket_endpoint)
app.websocket("/api/v1/stream")(websocket_endpoint)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    reload_mode = os.environ.get("ENVIRONMENT", "production").lower() == "development"
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port, reload=reload_mode)
