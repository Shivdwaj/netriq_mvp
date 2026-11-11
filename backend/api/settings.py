from fastapi import APIRouter, Depends, HTTPException, Request, status
from typing import Dict, Any, Optional
from pydantic import BaseModel
from backend.auth.roles import Capabilities, get_request_role
from backend.auth.permissions import require_permission
from backend.services.settings_service import settings_service
from backend.utils.logger import get_logger
from backend.self_defense.management_monitor import (
    management_monitor,
    ManagementSecurityError,
    FailClosedAuditError,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/settings", tags=["settings"])


from pydantic import BaseModel, Field

class SettingsUpdateReq(BaseModel):
    """Typed allowlist for system settings. Only these keys can be updated via the API."""
    firewall_adapter_type: Optional[str] = None
    quarantine_mode: Optional[str] = None
    sandbox_mode: Optional[str] = None
    threat_retention_days: Optional[int] = Field(None, ge=1, le=365)
    login_max_attempts: Optional[int] = Field(None, ge=1, le=20)
    login_lockout_minutes: Optional[int] = Field(None, ge=1, le=1440)
    anomaly_detector_enabled: Optional[bool] = None
    high_anomaly_threshold: Optional[float] = Field(None, ge=0.0, le=100.0)
    zero_day_weight: Optional[float] = Field(None, ge=0.0, le=1.0)
    heuristic_min_rules_for_quarantine: Optional[int] = Field(None, ge=1, le=10)
    layer1_threshold: Optional[float] = Field(None, ge=0.1, le=1.0)
    layer2_threshold: Optional[float] = Field(None, ge=0.1, le=1.0)
    auto_quarantine: Optional[bool] = None


@router.get("", response_model=Dict[str, Any], dependencies=[Depends(require_permission(Capabilities.MANAGE_SETTINGS))])
async def get_settings():
    try:
        return await settings_service.get_settings()
    except Exception as e:
        logger.error(f"Failed to retrieve settings: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve settings")


@router.patch("", response_model=Dict[str, Any], dependencies=[Depends(require_permission(Capabilities.MANAGE_SETTINGS))])
async def update_settings(updates: SettingsUpdateReq, req: Request):
    user = getattr(req.state, "user", {}) or {}
    actor_id = user.get("sub") or user.get("email") or "admin"
    tenant_id = user.get("tenant_id", "default")

    # MSM Anomaly & Rate Check
    try:
        management_monitor.check_admin_rate_limits(actor_id=actor_id, action="UPDATE_SETTINGS", tenant_id=tenant_id)
    except ManagementSecurityError as mse:
        raise HTTPException(status_code=mse.status_code, detail=str(mse))

    # Convert to dict, dropping keys the admin left unset
    updates_dict = {k: v for k, v in updates.model_dump(exclude_unset=True).items() if v is not None}

    # Mandatory Fail-Closed Audit Enforcement
    try:
        await management_monitor.enforce_mutation_audit(
            action="UPDATE_SETTINGS",
            actor=user,
            resource_type="settings",
            resource_id="system_settings",
            details=updates_dict,
            tenant_id=tenant_id
        )
    except FailClosedAuditError as fce:
        raise HTTPException(status_code=fce.status_code, detail=str(fce))

    try:
        return await settings_service.update_settings(get_request_role(req), updates_dict)
    except Exception as e:
        logger.error(f"Failed to update settings: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update settings")

