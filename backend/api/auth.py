from typing import Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from backend.schemas.auth import LoginRequest, RefreshRequest, RegisterRequest, TokenResponse
from backend.schemas.response import MessageResponse
from backend.auth.auth_service import AuthService
from backend.database.collections import users_repo
from backend.auth.roles import Capabilities, Role
from backend.auth.permissions import require_permission
from backend.auth.exceptions import (
    InvalidCredentialsError,
    AccountLockedError,
    TokenExpiredError,
    InvalidTokenError,
    WeakPasswordError
)
from backend.database.exceptions import DocumentNotFoundError
from backend.utils.logger import get_logger
from backend.self_defense.management_monitor import (
    management_monitor,
    ManagementSecurityError,
    FailClosedAuditError,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])
auth_service = AuthService()

class InitialSetupRequest(BaseModel):
    email: str
    password: str
    username: Optional[str] = None

@router.post("/setup")
async def initial_setup(request: InitialSetupRequest):
    """
    First-time administrator setup endpoint.
    Only accessible if no administrator account exists in the database.
    Once initialized, this endpoint is permanently locked (HTTP 403 Forbidden).
    """
    admins = await users_repo.list({"role": Role.ADMIN.value}, limit=1)
    if admins:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="System setup has already been completed. Setup mode is permanently disabled."
        )

    try:
        user_id = await auth_service.register_user(
            admin_user_id="initial_setup",
            email=request.email,
            raw_password=request.password,
            role=Role.ADMIN,
            username=request.username
        )
        logger.info(f"[AuthService] Initial administrator account '{request.email}' created successfully.")
        return {
            "success": True,
            "message": "Initial administrator account created successfully. System setup completed.",
            "user_id": user_id,
            "email": request.email,
            "role": "admin"
        }
    except (InvalidCredentialsError, WeakPasswordError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"[AuthService] Initial setup failed: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to initialize administrator.")

@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, req: Request):
    client_ip = req.client.host if req.client else "unknown"
    candidate_id = request.resolved_identity
    # Management Security Monitor Canary Token Check
    is_canary = await management_monitor.check_canary_probe(
        candidate_value=candidate_id,
        source_ip=client_ip,
        endpoint="/api/v1/auth/login",
        method="POST"
    )
    if is_canary:
        # Deliberately return standard generic 401 without revealing canary detection
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    try:
        result = await auth_service.login(candidate_id, request.password)
        return TokenResponse(**result)
    except InvalidCredentialsError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except AccountLockedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: RefreshRequest):
    try:
        result = await auth_service.refresh_token(request.refresh_token)
        return TokenResponse(**result)
    except (TokenExpiredError, InvalidTokenError) as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

@router.post("/logout", response_model=MessageResponse)
async def logout(request: Request, refresh_req: RefreshRequest):
    user = getattr(request.state, "user", None)
    user_id = user.get("sub") if user else None
    
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
    
    success = await auth_service.logout(user_id)
    return MessageResponse(message="Logged out successfully.", success=success)

@router.post("/register", response_model=MessageResponse, dependencies=[Depends(require_permission(Capabilities.MANAGE_USERS))])
async def register(request: RegisterRequest, req: Request):
    admin_user = getattr(req.state, "user", {}) or {}
    admin_id = admin_user.get("sub") or admin_user.get("email") or "admin"
    tenant_id = admin_user.get("tenant_id", "default")

    # Management Security Monitor Rate Limit & Anomaly Check
    try:
        management_monitor.check_admin_rate_limits(actor_id=admin_id, action="REGISTER_USER", tenant_id=tenant_id)
    except ManagementSecurityError as mse:
        raise HTTPException(status_code=mse.status_code, detail=str(mse))

    # Mandatory Fail-Closed Audit Enforcement
    try:
        await management_monitor.enforce_mutation_audit(
            action="REGISTER_USER",
            actor=admin_user,
            resource_type="user",
            resource_id=request.email,
            details={"email": request.email, "role": str(request.role)},
            tenant_id=tenant_id
        )
    except FailClosedAuditError as fce:
        raise HTTPException(status_code=fce.status_code, detail=str(fce))

    try:
        await auth_service.register_user(
            admin_user_id=admin_id,
            email=request.email,
            raw_password=request.password,
            role=request.role
        )
        return MessageResponse(message=f"User {request.email} registered successfully.", success=True)
    except (InvalidCredentialsError, WeakPasswordError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.get("/me")
async def get_me(request: Request):
    try:
        user = getattr(request.state, "user", None)
        if not user or not user.get("sub"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
        
        user_id = user.get("sub")
        import asyncio
        user_res = users_repo.get(user_id)
        user_doc = await user_res if (asyncio.iscoroutine(user_res) or hasattr(user_res, "__await__")) else user_res
        if not user_doc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User profile not found.")
        
        role_str = user_doc.get("role", "viewer")
        from backend.auth.roles import Role, PERMISSION_MATRIX
        try:
            role_enum = Role(role_str)
            capabilities = [cap.value for cap in PERMISSION_MATRIX.get(role_enum, [])]
        except Exception:
            capabilities = []
            
        return {
            "id": str(user_doc.get("_id", user_id)),
            "email": user_doc.get("email"),
            "username": user_doc.get("email", "").split("@")[0],
            "role": role_str,
            "capabilities": capabilities,
            "is_active": user_doc.get("is_active", True)
        }
    except HTTPException:
        raise
    except DocumentNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User profile not found.")
    except Exception as e:
        logger.error(f"[get_me] Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error.")
