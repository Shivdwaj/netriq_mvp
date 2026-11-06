from typing import List, Dict, Any, Union, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Header, status
from pydantic import BaseModel

from backend.auth.roles import Capabilities, Role, get_request_role
from backend.auth.permissions import require_permission
from backend.utils.logger import get_logger
from backend.pipeline import event_bus
from backend.adapters import suricata_adapter, zeek_adapter
from backend.services.central_management_service import central_management_service
from backend.schemas.management import (
    SensorRegistrationReq,
    SensorRegistrationResponse,
    SensorHeartbeatReq,
    SensorItem
)
from backend.database.collections import sensors_repo
import hashlib
import time
import json
from datetime import datetime

logger = get_logger(__name__)
router = APIRouter(prefix="/sensors", tags=["sensors"])

class IngestResponse(BaseModel):
    status: str
    events_ingested: int
    events_published: int

# Replay protection: cache recent event hashes (sliding memory set)
_INGEST_REPLAY_CACHE = set()
_MAX_REPLAY_CACHE = 100000

async def require_sensor_identity(req: Request) -> Dict[str, Any]:
    """
    Dedicated sensor-ingestion permission dependency (Critical Security Fix).
    Enforces that callers submitting telemetry must authenticate as a registered sensor
    via 'X-Sensor-Key' or 'Authorization: Bearer <sensor-token>'.
    """
    auth_user = getattr(req.state, "user", None)
    x_sensor_key = req.headers.get("X-Sensor-Key")

    if not auth_user and x_sensor_key:
        try:
            key_hash = hashlib.sha256(x_sensor_key.encode("utf-8")).hexdigest()
            sensors = await sensors_repo.list(filter_query={"api_key_hash": key_hash}, limit=1)
            if sensors:
                s = sensors[0]
                auth_user = {
                    "sub": s["sensor_id"],
                    "sensor_id": s["sensor_id"],
                    "username": s.get("name", "sensor"),
                    "role": "sensor",
                    "tenant_id": s.get("tenant_id", "default"),
                    "software_type": s.get("software_type", "sensor")
                }
                req.state.user = auth_user
        except Exception as e:
            logger.warning(f"Error checking sensor API key: {e}")

    if not auth_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sensor authentication required: Provide a valid 'X-Sensor-Key' header or Bearer token."
        )

    user_role = auth_user.get("role")
    if user_role not in (Role.ADMIN.value, "sensor", "sensor_ingest", Role.ANALYST.value):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Caller lacks sensor telemetry ingestion permissions."
        )

    return auth_user

def _get_request_tenant(req: Request) -> str:
    """Extracts tenant_id from authenticated token/key or X-Tenant-ID header."""
    auth_user = getattr(req.state, "user", None)
    if isinstance(auth_user, dict) and auth_user.get("tenant_id"):
        return auth_user.get("tenant_id")
    return req.headers.get("X-Tenant-ID", "default")

def _get_request_user(req: Request) -> str:
    """Extracts username or identity from request auth state."""
    auth_user = getattr(req.state, "user", None)
    if isinstance(auth_user, dict):
        return auth_user.get("username") or auth_user.get("sub") or "analyst@netriq.local"
    if isinstance(auth_user, str):
        return auth_user
    return "analyst@netriq.local"


# --- Sensor Registration & Health (A. Local sensor -> Central platform) ---

@router.post("/register", response_model=SensorRegistrationResponse)
async def register_sensor(body: SensorRegistrationReq, req: Request):
    """
    Registers a software sensor daemon (Suricata, Zeek, or NetrIQ Collector).
    Returns sensor credentials (api_key and sensor_token) for subsequent ingestion authentication.
    """
    try:
        # If caller is an authenticated user, inherit their tenant_id
        auth_user = getattr(req.state, "user", None)
        if isinstance(auth_user, dict) and auth_user.get("tenant_id") and auth_user.get("tenant_id") != "global":
            body.tenant_id = auth_user.get("tenant_id")

        resp = await central_management_service.register_software_sensor(body)
        return resp
    except Exception as e:
        logger.error(f"[SensorIngest API] Failed to register sensor: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to register sensor")


@router.post("/heartbeat")
async def report_sensor_heartbeat(
    body: SensorHeartbeatReq,
    req: Request,
    x_sensor_key: Optional[str] = Header(None, alias="X-Sensor-Key")
):
    """
    Reports periodic heartbeat telemetry from a running software daemon.
    Monitors CPU %, RAM usage, software packet drops (kernel_drops), and uptime.
    """
    try:
        # Validate authentication if key is provided or present in state
        auth_user = getattr(req.state, "user", None)
        if not auth_user and x_sensor_key:
            auth_sensor = await central_management_service.authenticate_sensor(body.sensor_id, x_sensor_key)
            if not auth_sensor:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid sensor API key")

        return await central_management_service.record_sensor_heartbeat(body)
    except HTTPException:
        raise
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(val_err))
    except Exception as e:
        logger.error(f"[SensorIngest API] Failed to record heartbeat: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to record sensor heartbeat")


@router.get("/config")
async def get_sensor_configuration(
    req: Request,
    sensor_id: Optional[str] = None
):
    """
    Retrieves sensor configuration (listening interface, buffer sizes, logging levels).
    Can be retrieved by the authenticated sensor itself or by an administrator.
    """
    try:
        auth_user = getattr(req.state, "user", None)
        if not auth_user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

        # Resolve sensor_id
        target_sensor_id = sensor_id or auth_user.get("sensor_id") or auth_user.get("sub")
        if not target_sensor_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="sensor_id must be provided")

        tenant_id = _get_request_tenant(req)
        filter_q = {"sensor_id": target_sensor_id}
        if auth_user.get("role") != Role.ADMIN and tenant_id != "global":
            filter_q["tenant_id"] = tenant_id

        sensors = await sensors_repo.list(filter_query=filter_q, limit=1)
        if not sensors:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Sensor '{target_sensor_id}' not found")

        sensor = sensors[0]
        return {
            "sensor_id": sensor.get("sensor_id"),
            "tenant_id": sensor.get("tenant_id"),
            "name": sensor.get("name"),
            "software_type": sensor.get("software_type"),
            "software_version": sensor.get("software_version"),
            "listening_interface": sensor.get("listening_interface", "eth0"),
            "config": sensor.get("config", {
                "capture_interface": sensor.get("listening_interface", "eth0"),
                "buffer_size_mb": 256,
                "log_level": "INFO"
            })
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[SensorIngest API] Failed to retrieve sensor config: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve sensor configuration")


# --- Sensor List (B. Dashboard -> Backend) ---

@router.get("", response_model=List[SensorItem])
async def list_sensors(req: Request):
    """
    View registered software sensors and their health status.
    Scoped strictly to the caller's organization.
    """
    try:
        tenant_id = _get_request_tenant(req)
        sensors = await central_management_service.list_software_sensors(tenant_id)
        return [SensorItem(**s) for s in sensors]
    except Exception as e:
        logger.error(f"[SensorIngest API] Failed to list sensors: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to list sensors")


@router.get("/{sensor_id}/pcap", dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def get_selective_pcap(
    sensor_id: str,
    req: Request,
    incident_id: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    flow_id: Optional[str] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    max_packets: int = 50
):
    """
    On-Demand Selective PCAP Retrieval for SOC Analyst Investigations.
    
    Architectural Mandate:
    Raw packet payloads stay local on the sensor PCAP ring buffer.
    Only when an incident requires forensic packet drill-down does an authorized analyst
    request the targeted slice for the specific flow and timeframe.
    When incident_id is provided, the retrieved slice is stored as external evidence and audited.
    """
    try:
        tenant_id = _get_request_tenant(req)
        user = _get_request_user(req)
        pcap_data = await central_management_service.retrieve_selective_pcap(
            sensor_id=sensor_id,
            tenant_id=tenant_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            flow_id=flow_id,
            start_time=start_time,
            end_time=end_time,
            max_packets=max_packets
        )

        # If incident_id is provided, save evidence and audit
        if incident_id and pcap_data.get("packets"):
            from backend.services.evidence_service import evidence_service
            from backend.schemas.entities import AuditAction

            stored_evidence = await evidence_service.store_selective_pcap(
                tenant_id=tenant_id,
                incident_id=incident_id,
                sensor_id=sensor_id,
                packets=pcap_data.get("packets", []),
                filter_criteria={"src_ip": src_ip, "dst_ip": dst_ip, "flow_id": flow_id}
            )
            pcap_data["evidence_id"] = stored_evidence.evidence_id
            pcap_data["file_hash_sha256"] = stored_evidence.file_hash_sha256
            pcap_data["file_path"] = stored_evidence.file_path

            await evidence_service.log_audit_action(
                tenant_id=tenant_id,
                user_id=user,
                username=user,
                action=AuditAction.PCAP_EXTRACT,
                resource_type="evidence",
                resource_id=stored_evidence.evidence_id,
                details={
                    "sensor_id": sensor_id,
                    "incident_id": incident_id,
                    "packet_count": len(pcap_data.get("packets", [])),
                    "file_path": stored_evidence.file_path,
                    "file_hash": stored_evidence.file_hash_sha256
                }
            )

        return pcap_data
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except Exception as e:
        logger.error(f"[SensorIngest API] Failed to retrieve selective PCAP: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve selective PCAP")


# --- Secure Raw Ingestion Adapters (Suricata EVE & Zeek logs) ---

def _validate_and_filter_records(
    records: List[Dict[str, Any]],
    now: float
) -> List[Dict[str, Any]]:
    """Enforces replay protection and timestamp freshness filtering."""
    valid = []
    for rec in records:
        if not isinstance(rec, dict):
            continue

        # Replay check via record signature
        rec_hash = hashlib.sha256(json.dumps(rec, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        if rec_hash in _INGEST_REPLAY_CACHE:
            logger.warning("[SensorIngest] Duplicate event hash detected; dropping potential replay.")
            continue

        # Timestamp freshness check (allow window: past 24 hours to future 5 minutes)
        ts = rec.get("timestamp") or rec.get("ts")
        if ts:
            try:
                if isinstance(ts, (int, float)):
                    event_time = float(ts)
                else:
                    clean_ts = str(ts).replace("Z", "+00:00")
                    event_time = datetime.fromisoformat(clean_ts).timestamp()
                if (now - event_time) > 86400 or (event_time - now) > 300:
                    logger.warning(f"[SensorIngest] Stale or future event timestamp detected ({ts}); dropping.")
                    continue
            except Exception:
                pass

        if len(_INGEST_REPLAY_CACHE) >= _MAX_REPLAY_CACHE:
            _INGEST_REPLAY_CACHE.clear()
        _INGEST_REPLAY_CACHE.add(rec_hash)
        valid.append(rec)
    return valid

@router.post("/suricata/eve", response_model=IngestResponse, dependencies=[Depends(require_sensor_identity)])
async def ingest_suricata_eve(
    payload: Union[Dict[str, Any], List[Dict[str, Any]]],
    req: Request
):
    """
    Ingests Suricata EVE JSON alerts, anomalies, or protocol events.
    Requires authenticated sensor machine identity (X-Sensor-Key or Bearer token).
    Enforces payload size limits, schema validation, and replay protection.
    """
    try:
        records = [payload] if isinstance(payload, dict) else payload
        if not records:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Payload cannot be empty.")
        if len(records) > 1000:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Batch limit exceeded: Maximum 1,000 events per ingestion request.")

        tenant_id = _get_request_tenant(req)
        now = time.time()
        filtered_records = _validate_and_filter_records(records, now)

        published = 0
        for rec in filtered_records:
            event = suricata_adapter.transform(rec)
            if event:
                event.tenant_id = tenant_id
                await event_bus.publish(event)
                published += 1

        return IngestResponse(
            status="success",
            events_ingested=len(filtered_records),
            events_published=published
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[SensorIngest API] Error ingesting Suricata EVE: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to ingest Suricata EVE")

@router.post("/zeek/conn", response_model=IngestResponse, dependencies=[Depends(require_sensor_identity)])
async def ingest_zeek_conn(
    payload: Union[Dict[str, Any], List[Dict[str, Any]]],
    req: Request
):
    """
    Ingests Zeek conn.log records describing connection state, duration, and session metrics.
    Requires authenticated sensor machine identity (X-Sensor-Key or Bearer token).
    Enforces payload size limits, schema validation, and replay protection.
    """
    try:
        records = [payload] if isinstance(payload, dict) else payload
        if not records:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Payload cannot be empty.")
        if len(records) > 1000:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Batch limit exceeded: Maximum 1,000 events per ingestion request.")

        tenant_id = _get_request_tenant(req)
        now = time.time()
        filtered_records = _validate_and_filter_records(records, now)

        published = 0
        for rec in filtered_records:
            event = zeek_adapter.transform(rec)
            if event:
                event.tenant_id = tenant_id
                await event_bus.publish(event)
                published += 1

        return IngestResponse(
            status="success",
            events_ingested=len(filtered_records),
            events_published=published
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[SensorIngest API] Error ingesting Zeek conn: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to ingest Zeek conn logs")

@router.post("/zeek/dns", response_model=IngestResponse, dependencies=[Depends(require_sensor_identity)])
async def ingest_zeek_dns(
    payload: Union[Dict[str, Any], List[Dict[str, Any]]],
    req: Request
):
    """
    Ingests Zeek dns.log records describing domain queries and IP resolutions.
    Requires authenticated sensor machine identity (X-Sensor-Key or Bearer token).
    Enforces payload size limits, schema validation, and replay protection.
    """
    try:
        records = [payload] if isinstance(payload, dict) else payload
        if not records:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Payload cannot be empty.")
        if len(records) > 1000:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Batch limit exceeded: Maximum 1,000 events per ingestion request.")

        tenant_id = _get_request_tenant(req)
        now = time.time()
        filtered_records = _validate_and_filter_records(records, now)

        published = 0
        for rec in filtered_records:
            event = zeek_adapter.transform(rec)
            if event:
                event.tenant_id = tenant_id
                await event_bus.publish(event)
                published += 1

        return IngestResponse(
            status="success",
            events_ingested=len(filtered_records),
            events_published=published
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[SensorIngest API] Error ingesting Zeek DNS: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to ingest Zeek DNS logs")
