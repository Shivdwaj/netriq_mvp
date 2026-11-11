import asyncio
import json
import time
import os
from typing import Dict
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from backend.auth.jwt_handler import verify_token
from backend.auth.exceptions import TokenExpiredError, InvalidTokenError
from backend.auth.roles import Role
from backend.websocket.manager import manager
from backend.database.collections import users_repo
from backend.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["websocket"])

# Configurable limits
MAX_PREAUTH_PER_IP = int(os.getenv("WS_MAX_PREAUTH_PER_IP", "5"))
MAX_PAYLOAD_BYTES = int(os.getenv("WS_MAX_PAYLOAD_BYTES", "65536"))  # 64 KB
SESSION_CHECK_INTERVAL_SECONDS = 60

# Concurrency tracker for unauthenticated connections per client IP
_preauth_connections: Dict[str, int] = {}
_preauth_lock = asyncio.Lock()


async def _acquire_preauth_slot(client_ip: str) -> bool:
    """Limits concurrent unauthenticated WebSocket connections per IP to prevent socket exhaustion."""
    async with _preauth_lock:
        count = _preauth_connections.get(client_ip, 0)
        if count >= MAX_PREAUTH_PER_IP:
            return False
        _preauth_connections[client_ip] = count + 1
        return True


async def _release_preauth_slot(client_ip: str):
    """Releases the unauthenticated connection slot for the IP."""
    async with _preauth_lock:
        if client_ip in _preauth_connections:
            _preauth_connections[client_ip] = max(0, _preauth_connections[client_ip] - 1)
            if _preauth_connections[client_ip] == 0:
                del _preauth_connections[client_ip]


@router.websocket("/ws")
@router.websocket("/api/v1/ws")
@router.websocket("/api/v1/stream")
async def websocket_endpoint(websocket: WebSocket):
    """
    Hardened Live Updates WebSocket endpoint (WS /api/v1/stream, WS /ws).
    Streams real-time incident notifications, threat detections, and telemetry.
    
    Security Controls:
    1. Pre-auth connection concurrency limit per IP (prevents file descriptor exhaustion).
    2. Strict 5-second authentication handshake timeout.
    3. Maximum frame size enforcement (64 KB) to prevent memory allocation attacks.
    4. Periodic session & role re-validation to revoke access for locked/deactivated accounts.
    """
    client_ip = websocket.client.host if websocket.client else "unknown"

    slot_acquired = await _acquire_preauth_slot(client_ip)
    if not slot_acquired:
        logger.warning(f"[WebSocket] Connection rejected: Pre-auth concurrency limit reached for IP {client_ip}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    token = websocket.query_params.get("token")
    user_id = None
    role = None

    try:
        if not token:
            # Wait for auth handshake message with a strict 5.0-second timeout
            try:
                raw_auth_msg = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("WebSocket auth failed: Handshake timed out after 5 seconds")
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return
            except Exception:
                logger.warning("WebSocket auth failed: Connection terminated during handshake")
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return

            if len(raw_auth_msg.encode("utf-8")) > MAX_PAYLOAD_BYTES:
                logger.warning("WebSocket auth failed: Handshake payload exceeded size limit")
                await websocket.close(code=1009)  # WS_1009_MESSAGE_TOO_BIG
                return

            try:
                auth_msg = json.loads(raw_auth_msg)
            except Exception:
                logger.warning("WebSocket auth failed: Invalid JSON in handshake")
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return

            if not auth_msg or auth_msg.get("type") != "auth" or not auth_msg.get("token"):
                logger.warning("WebSocket: missing or malformed auth handshake")
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return

            token = auth_msg["token"]

        try:
            payload = verify_token(token, expected_type="access")
        except (TokenExpiredError, InvalidTokenError) as e:
            logger.warning(f"WebSocket auth failed: Invalid or expired token ({e})")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        user_id = payload.get("sub")
        role_str = payload.get("role", "viewer")
        tenant_id = payload.get("tenant_id") or "default"

        try:
            role = Role(role_str)
        except ValueError:
            logger.warning(f"WebSocket auth failed: unknown role '{role_str}'")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

    finally:
        # Release pre-auth slot once authenticated or rejected
        await _release_preauth_slot(client_ip)

    # Register with the canonical role-aware and tenant-isolated ConnectionManager
    await manager.connect(user_id, role, websocket, tenant_id=tenant_id)
    logger.info(f"WebSocket connected: user={user_id} role={role.value} tenant={tenant_id} ip={client_ip}")

    # Confirm auth success to client
    await websocket.send_json({"type": "auth_ok", "user_id": user_id, "role": role.value, "tenant_id": tenant_id})

    last_session_check = time.time()

    try:
        while True:
            # Receive raw text frame to enforce size limit before JSON deserialization
            raw_text = await websocket.receive_text()
            if len(raw_text.encode("utf-8")) > MAX_PAYLOAD_BYTES:
                logger.warning(f"[WebSocket] Message payload too large ({len(raw_text)} bytes) from user {user_id}")
                await websocket.close(code=1009)  # WS_1009_MESSAGE_TOO_BIG
                break

            try:
                data = json.loads(raw_text)
            except Exception:
                continue

            # Keep-alive: echo pings
            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})

            # Periodic active session / role re-validation
            now = time.time()
            if now - last_session_check > SESSION_CHECK_INTERVAL_SECONDS:
                last_session_check = now
                user = await users_repo.get(user_id)
                if not user or not user.get("is_active", True) or user.get("locked_until", 0) > now:
                    logger.warning(f"[WebSocket] Account locked/inactive for user {user_id}. Terminating WebSocket session.")
                    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                    break

    except WebSocketDisconnect:
        await manager.disconnect(user_id, role, websocket, tenant_id=tenant_id)
        logger.info(f"WebSocket disconnected: user={user_id}")
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id}: {e}")
        await manager.disconnect(user_id, role, websocket, tenant_id=tenant_id)
