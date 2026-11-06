from fastapi import APIRouter, Depends, HTTPException, Request, status
from typing import List, Optional
from backend.schemas.threat import RawLog, LogQuery
from backend.auth.roles import Capabilities, Role, get_request_role
from backend.auth.permissions import require_permission
from backend.services.history_service import history_service
from backend.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/threats", tags=["threats"])

@router.get("", response_model=List[RawLog], dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def list_threats(req: Request, query: LogQuery = Depends()):
    """
    Capability: Retrieve detection alerts and classifications for SOC dashboard & analysts.
    Enforces organization-level multitenant authorization.
    """
    try:
        filters = {}
        if query.severity and query.severity.upper() != "ALL":
            filters["severity"] = query.severity.lower()
        if query.search:
            s = query.search.strip()
            filters["$or"] = [
                {"src_ip": {"$regex": s, "$options": "i"}},
                {"dst_ip": {"$regex": s, "$options": "i"}},
                {"prediction": {"$regex": s, "$options": "i"}},
            ]
        elif query.ip:
            filters["$or"] = [
                {"src_ip": query.ip.strip()},
                {"dst_ip": query.ip.strip()},
            ]
        else:
            if query.src_ip:
                filters["src_ip"] = query.src_ip.strip()
            if query.dst_ip:
                filters["dst_ip"] = query.dst_ip.strip()
        if query.start_time is not None:
            filters.setdefault("timestamp", {})["$gte"] = query.start_time
        if query.end_time is not None:
            filters.setdefault("timestamp", {})["$lte"] = query.end_time

        # Multitenancy scoping
        auth_user = getattr(req.state, "user", None)
        if isinstance(auth_user, dict) and auth_user.get("tenant_id") and auth_user.get("tenant_id") != "global":
            filters["tenant_id"] = auth_user.get("tenant_id")

        role = get_request_role(req)
        results = await history_service.get_raw_logs(role=role, filters=filters, limit=query.limit, skip=query.offset)
        return [RawLog(**item) for item in results]
    except Exception as e:
        logger.error(f"[ThreatsAPI] Failed to retrieve detection alerts: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve threats")

