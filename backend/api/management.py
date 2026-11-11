import os
from fastapi import APIRouter, Depends, HTTPException, Request, Header, status
from typing import List, Dict, Any, Optional

from backend.schemas.management import (
    OrganisationCreateReq,
    OrganisationItem,
    SensorRegistrationReq,
    SensorRegistrationResponse,
    SensorHeartbeatReq,
    SensorItem,
    SensorConfigUpdateReq,
    DetectionRuleManifest
)
from backend.auth.roles import Capabilities, get_request_role, Role
from backend.auth.permissions import require_permission
from backend.services.central_management_service import central_management_service
from backend.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/management", tags=["management"])


def _get_request_tenant(req: Request) -> str:
    """
    Extracts tenant_id securely.
    - Role.ADMIN can specify/override tenant_id via 'X-Tenant-ID' header or query param.
    - Regular users are strictly bound to their authenticated token tenant claim.
    - Software sensors are bound to their authenticated sensor profile.
    - Arbitrary X-Tenant-ID headers from unauthenticated/non-admin callers are rejected.
    """
    auth_user = getattr(req.state, "user", None)
    role = get_request_role(req)

    # 1. Administrator can query any tenant or override via header
    if role == Role.ADMIN:
        requested = req.headers.get("X-Tenant-ID") or req.query_params.get("tenant_id")
        if requested:
            return requested
        if isinstance(auth_user, dict) and auth_user.get("tenant_id"):
            return auth_user.get("tenant_id")
        return "default"

    # 2. Authenticated non-admin user must strictly use their assigned tenant
    if isinstance(auth_user, dict) and auth_user.get("sub"):
        user_tenant = auth_user.get("tenant_id")
        if user_tenant:
            # If user provided a conflicting X-Tenant-ID header, deny cross-tenant spoofing
            header_tenant = req.headers.get("X-Tenant-ID")
            if header_tenant and header_tenant != user_tenant:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Cross-tenant access prohibited: User belongs to '{user_tenant}'."
                )
            return user_tenant
        return "default"

    # 3. Authenticated sensor identity on request state
    auth_sensor = getattr(req.state, "sensor", None)
    if isinstance(auth_sensor, dict) and auth_sensor.get("tenant_id"):
        return auth_sensor["tenant_id"]

    # 4. Fallback in test/dev environment if explicitly testing
    if os.getenv("TESTING", "").lower() == "true":
        return req.headers.get("X-Tenant-ID", "default")

    # Unauthenticated caller attempting to supply arbitrary tenant
    header_tenant = req.headers.get("X-Tenant-ID")
    if header_tenant:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to access organization resources."
        )
    return "default"


# --- Organisation Management Endpoints ---
@router.post("/organisations", response_model=OrganisationItem, dependencies=[Depends(require_permission(Capabilities.CREATE_ORGANIZATION))])
async def register_organisation(body: OrganisationCreateReq):
    """
    Capability 1: Organisation Registration.
    Creates a new isolated customer organisation with its own tenant_id.
    """
    try:
        org = await central_management_service.create_organisation(body)
        return OrganisationItem(**org)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as e:
        logger.error(f"Failed to register organisation: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create organisation")


@router.get("/organisations", response_model=List[OrganisationItem], dependencies=[Depends(require_permission(Capabilities.VIEW_SYSTEM_METRICS))])
async def list_organisations():
    """Lists all customer organisations (Multi-tenant Admin)."""
    try:
        orgs = await central_management_service.list_organisations()
        return [OrganisationItem(**o) for o in orgs]
    except Exception as e:
        logger.error(f"Failed to list organisations: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list organisations")


@router.get("/organisations/{tenant_id}", response_model=OrganisationItem)
async def get_organisation(tenant_id: str, req: Request):
    """Enforces tenant isolation: users can only access their own organisation."""
    user_tenant = _get_request_tenant(req)
    role = get_request_role(req)
    if role != Role.ADMIN and user_tenant != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Cross-organisation queries prohibited.")

    org = await central_management_service.get_organisation(tenant_id)
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
    return OrganisationItem(**org)


# --- Software Sensor Management Endpoints ---
@router.post("/sensors/register", response_model=SensorRegistrationResponse)
async def register_software_sensor(body: SensorRegistrationReq, req: Request):
    """
    Capabilities 2 & 3: Sensor Registration & Authentication.
    Registers a software daemon (Suricata, Zeek, or NetrIQ Collector) running on a VM or container.
    Requires Role.ADMIN, MANAGE_ORGANIZATIONS capability, or authenticated member of the specified tenant.
    """
    auth_user = getattr(req.state, "user", None)
    role = get_request_role(req)
    is_testing = os.getenv("TESTING", "").lower() == "true"

    if not is_testing:
        if not auth_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required to register software sensors."
            )
        if role != Role.ADMIN:
            user_tenant = auth_user.get("tenant_id")
            if user_tenant and user_tenant != body.tenant_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cannot register software sensor for a foreign organisation."
                )

    try:
        resp = await central_management_service.register_software_sensor(body)
        return resp
    except Exception as e:
        logger.error(f"Failed to register software sensor: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to register software sensor")


@router.post("/sensors/heartbeat")
async def record_sensor_heartbeat(
    body: SensorHeartbeatReq,
    x_sensor_key: Optional[str] = Header(None, alias="X-Sensor-Key")
):
    """
    Capability 4: Sensor Health Monitoring.
    Receives periodic heartbeat telemetry from running software daemons.
    Enforces mandatory X-Sensor-Key authentication.
    """
    if not x_sensor_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required sensor authentication key (X-Sensor-Key)."
        )

    auth_sensor = await central_management_service.authenticate_sensor(body.sensor_id, x_sensor_key)
    if not auth_sensor:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or unauthorized sensor API key."
        )

    # Bind authenticated sensor ID to the submitted sensor ID
    if auth_sensor.get("sensor_id") != body.sensor_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Sensor identity mismatch: Authenticated sensor key does not match submitted sensor_id '{body.sensor_id}'."
        )

    try:
        return await central_management_service.record_sensor_heartbeat(body)
    except HTTPException:
        raise
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(val_err))
    except Exception as e:
        logger.error(f"Failed to record sensor heartbeat: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to record sensor heartbeat")


@router.get("/sensors", response_model=List[SensorItem], dependencies=[Depends(require_permission(Capabilities.VIEW_SYSTEM_METRICS))])
async def list_software_sensors(req: Request):
    """Lists active software sensors scoped strictly to the caller's organisation."""
    try:
        tenant_id = _get_request_tenant(req)
        sensors = await central_management_service.list_software_sensors(tenant_id)
        return [SensorItem(**s) for s in sensors]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list sensors: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list sensors")


# --- Detection Rule Distribution ---
@router.get("/sensors/{sensor_id}/rules", response_model=DetectionRuleManifest)
async def get_sensor_rules(
    sensor_id: str,
    req: Request,
    x_sensor_key: Optional[str] = Header(None, alias="X-Sensor-Key")
):
    """
    Capability 5: Detection Rule Distribution.
    Software sensor pulls active Suricata and NetrIQ ruleset manifests for its tenant organisation.
    Authenticates either via X-Sensor-Key or an authenticated user session.
    """
    tenant_id = None
    if x_sensor_key:
        auth_sensor = await central_management_service.authenticate_sensor(sensor_id, x_sensor_key)
        if not auth_sensor:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid sensor API key")
        tenant_id = auth_sensor.get("tenant_id")
    else:
        role = get_request_role(req)
        auth_user = getattr(req.state, "user", None)
        if not auth_user and os.getenv("TESTING", "").lower() != "true":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required to retrieve rule manifest."
            )
        tenant_id = _get_request_tenant(req)

    try:
        manifest = await central_management_service.get_rule_manifest(tenant_id or "default")
        return manifest
    except Exception as e:
        logger.error(f"Failed to fetch rules for sensor {sensor_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve rule manifest")


# --- Remote Configuration Management ---
@router.patch("/sensors/{sensor_id}/config", response_model=SensorItem, dependencies=[Depends(require_permission(Capabilities.MANAGE_ORGANIZATIONS))])
async def update_sensor_configuration(sensor_id: str, body: SensorConfigUpdateReq, req: Request):
    """
    Capability 6: Configuration Management.
    Remotely updates configuration parameters for a software daemon (listening interface, buffers).
    Requires MANAGE_ORGANIZATIONS capability.
    """
    try:
        tenant_id = _get_request_tenant(req)
        updated = await central_management_service.update_sensor_config(tenant_id, sensor_id, body)
        return SensorItem(**updated)
    except HTTPException:
        raise
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(val_err))
    except Exception as e:
        logger.error(f"Failed to update sensor config: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update sensor config")


# --- Software Version Tracking ---
@router.get("/fleet/versions", dependencies=[Depends(require_permission(Capabilities.VIEW_SYSTEM_METRICS))])
async def get_fleet_version_matrix(req: Request):
    """
    Capability 8: Software Version Tracking.
    Returns an audit table of all daemon versions across customer VMs/containers vs current benchmarks.
    Requires VIEW_SYSTEM_METRICS capability.
    """
    try:
        tenant_id = _get_request_tenant(req)
        return await central_management_service.get_software_version_matrix(tenant_id)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve version matrix: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve software version matrix")
