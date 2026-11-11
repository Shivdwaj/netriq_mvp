from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from backend.schemas.analytics import TimeRangeQuery, TrendSeries, DataPoint
from backend.auth.roles import Capabilities, Role, get_request_role
from backend.auth.permissions import require_permission
from backend.services.analytics_service import analytics_service
from backend.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/analytics", tags=["analytics"])

def _get_request_tenant(req: Request) -> str:
    """Extracts tenant_id from auth state or X-Tenant-ID for Admin."""
    auth_user = getattr(req.state, "user", None)
    if isinstance(auth_user, dict) and auth_user.get("tenant_id"):
        return auth_user.get("tenant_id")
    role = get_request_role(req)
    if role == Role.ADMIN:
        return req.headers.get("X-Tenant-ID", "global")
    return "default"

@router.get("/kpis", dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def get_kpis(req: Request):
    try:
        role = get_request_role(req)
        tenant_id = _get_request_tenant(req)
        return await analytics_service.get_kpis(role=role, tenant_id=tenant_id)
    except Exception as e:
        logger.error(f"Failed to fetch analytics KPIs: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch analytics KPIs"
        )

@router.get("/trends", response_model=TrendSeries, dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def get_trends(req: Request, query: TimeRangeQuery = Depends()):
    try:
        role = get_request_role(req)
        tenant_id = _get_request_tenant(req)
        result = await analytics_service.get_trends(
            role=role,
            start_time=query.start_time,
            end_time=query.end_time,
            tenant_id=tenant_id
        )
        return TrendSeries.model_validate(result)
    except Exception as e:
        logger.error(f"Failed to fetch analytics trends: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch analytics"
        )

