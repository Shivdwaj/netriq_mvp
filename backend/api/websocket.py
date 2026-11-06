import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from backend.auth.jwt_handler import verify_token
from backend.auth.exceptions import TokenExpiredError, InvalidTokenError
from backend.auth.roles import Role
from backend.websocket.manager import manager
from backend.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["websocket"])


@router.websocket("/ws")
@router.websocket("/api/v1/ws")
@router.websocket("/api/v1/stream")
async def websocket_endpoint(websocket: WebSocket):
    """
    Live Updates WebSocket endpoint (WS /api/v1/stream, WS /ws).
    Streams real-time incident notifications, threat detections, and telemetry.
    
    Auth options:
    1. Query param: ?token=<access_token>
    2. First-message handshake within 5s: {"type": "auth", "token": "<access_token>"}
    """
    await websocket.accept()

    token = websocket.query_params.get("token")

    if not token:
        # Wait for auth handshake message with a strict 5.0-second timeout
        try:
            auth_msg = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning("WebSocket auth failed: Handshake timed out after 5 seconds")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
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

    try:
        role = Role(role_str)
    except ValueError:
        logger.warning(f"WebSocket auth failed: unknown role '{role_str}'")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Register with the canonical role-aware ConnectionManager
    await manager.connect(user_id, role, websocket)
    logger.info(f"WebSocket connected: user={user_id} role={role.value}")

    # Confirm auth success to client
    await websocket.send_json({"type": "auth_ok", "user_id": user_id, "role": role.value})

    try:
        while True:
            # Keep-alive: echo pings, ignore everything else
            data = await websocket.receive_json()
            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        await manager.disconnect(user_id, role, websocket)
        logger.info(f"WebSocket disconnected: user={user_id}")
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id}: {e}")
        await manager.disconnect(user_id, role, websocket)
