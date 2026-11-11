import time
import uuid
from typing import List, Dict, Any, Optional, Union
from fastapi import APIRouter, Depends, HTTPException, Request, Header, status
from pydantic import BaseModel, Field, field_validator

from backend.utils.logger import get_logger
from backend.auth.roles import Capabilities, Role, get_request_role
from backend.auth.permissions import require_permission
from backend.pipeline import event_bus
from backend.pipeline.schemas import (
    NormalizedSecurityEvent,
    get_utc_iso_now,
    format_utc_timestamp
)
from backend.database.collections import events_repo, threats_repo, idempotency_repo, sensors_repo
from backend.self_defense.pipeline_guard import (
    pipeline_guard,
    PipelineIntegrityError,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/events", tags=["events"])

# In-memory LRU idempotency cache for low-latency deduplication
_IDEMPOTENCY_CACHE = set()

# --- Schemas ---

class IngestEventItem(BaseModel):
    event_id: Optional[str] = None
    timestamp: Optional[Union[str, float, int]] = None
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = 0
    destination_port: Optional[int] = 0
    protocol: Optional[str] = "TCP"
    event_type: Optional[str] = "connection"
    detection_source: Optional[str] = "sensor"
    severity: Optional[str] = "INFO"
    evidence: Optional[Dict[str, Any]] = Field(default_factory=dict)

    # Permit extra attributes from Suricata/Zeek logs without rejecting payloads
    model_config = {"extra": "allow"}

class EventBatchIngestReq(BaseModel):
    sensor_id: str
    batch_id: str
    events: List[IngestEventItem]

    @field_validator("events")
    @classmethod
    def validate_events_size(cls, v):
        if not v:
            raise ValueError("Events list cannot be empty.")
        if len(v) > 1000:
            raise ValueError("Exceeded maximum batch ingestion limit (1,000 events per batch).")
        return v

class BatchIngestResponse(BaseModel):
    status: str
    batch_id: str
    sensor_id: str
    accepted_count: int
    duplicate_count: int
    accepted_event_ids: List[str]
    duplicate_event_ids: List[str]
    timestamp: str
    message: Optional[str] = None


def _extract_authenticated_tenant(req: Request) -> str:
    """
    OWASP Rule: Never trust a tenant_id supplied by an untrusted client.
    Extracts the securely verified tenant_id from the authenticated user or sensor context.
    """
    user = getattr(req.state, "user", None)
    if isinstance(user, dict) and user.get("tenant_id"):
        return user.get("tenant_id")
    return "default"


# --- Batch Ingestion Endpoint (A. Local sensor -> Central platform) ---

@router.post("/batch", response_model=BatchIngestResponse, status_code=status.HTTP_200_OK)
async def ingest_event_batch(
    payload: EventBatchIngestReq,
    req: Request,
    idempotency_key: Optional[str] = Header(None, alias="X-Idempotency-Key")
):
    """
    Submits a batch of collected events from a software sensor daemon.
    
    Security & Reliability Rules:
    - Authenticates the sensor via Bearer token or X-Sensor-Key.
    - Enforces organisation-level isolation: tenant_id is derived solely from authenticated credentials.
    - Idempotency: Deduplicates against batch_id and individual event_ids to allow safe retries.
    - Streams newly accepted events into the NetrIQ EventBus for Threat Intelligence & Correlation.
    """
    auth_user = getattr(req.state, "user", None)
    if not auth_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide valid sensor credentials."
        )

    tenant_id = _extract_authenticated_tenant(req)
    sensor_id = payload.sensor_id

    # Pipeline Integrity Guard Check (HMAC-SHA256, sequence CAS, freshness)
    raw_body = await req.body()
    try:
        verdict = await pipeline_guard.verify_request(
            raw_body=raw_body,
            headers=dict(req.headers),
            authenticated_sensor_id=sensor_id,
            authenticated_tenant_id=tenant_id
        )
    except PipelineIntegrityError as pie:
        raise HTTPException(status_code=pie.status_code, detail=str(pie))

    batch_id = payload.batch_id
    effective_idem_key = idempotency_key or batch_id

    # Check if the entire batch has already been processed (safe idempotent retry)
    cached_batch_key = f"batch:{payload.sensor_id}:{effective_idem_key}"
    if cached_batch_key in _IDEMPOTENCY_CACHE:
        all_ids = [e.event_id or f"{batch_id}-{idx}" for idx, e in enumerate(payload.events)]
        return BatchIngestResponse(
            status="acknowledged",
            batch_id=batch_id,
            sensor_id=payload.sensor_id,
            accepted_count=0,
            duplicate_count=len(payload.events),
            accepted_event_ids=[],
            duplicate_event_ids=all_ids,
            timestamp=get_utc_iso_now(),
            message="Batch previously processed; duplicate batch safely acknowledged."
        )

    # Check database persistence for batch idempotency
    existing_batch = await idempotency_repo.list(filter_query={"key": cached_batch_key}, limit=1)
    if existing_batch:
        _IDEMPOTENCY_CACHE.add(cached_batch_key)
        all_ids = [e.event_id or f"{batch_id}-{idx}" for idx, e in enumerate(payload.events)]
        return BatchIngestResponse(
            status="acknowledged",
            batch_id=batch_id,
            sensor_id=payload.sensor_id,
            accepted_count=0,
            duplicate_count=len(payload.events),
            accepted_event_ids=[],
            duplicate_event_ids=all_ids,
            timestamp=get_utc_iso_now(),
            message="Batch previously processed; duplicate batch safely acknowledged."
        )

    accepted_event_ids: List[str] = []
    duplicate_event_ids: List[str] = []
    new_event_docs: List[Dict[str, Any]] = []

    now_iso = get_utc_iso_now()

    for idx, raw_evt in enumerate(payload.events):
        evt_id = raw_evt.event_id or f"{batch_id}-{idx}"
        evt_cache_key = f"evt:{tenant_id}:{evt_id}"

        # Deduplication check
        if evt_cache_key in _IDEMPOTENCY_CACHE:
            duplicate_event_ids.append(evt_id)
            continue

        existing_evt = await idempotency_repo.list(filter_query={"key": evt_cache_key}, limit=1)
        if existing_evt:
            _IDEMPOTENCY_CACHE.add(evt_cache_key)
            duplicate_event_ids.append(evt_id)
            continue

        # Valid newly accepted event
        accepted_event_ids.append(evt_id)
        _IDEMPOTENCY_CACHE.add(evt_cache_key)

        ts_formatted = format_utc_timestamp(raw_evt.timestamp)

        # Normalize into NetrIQ Common Event Format (NCEF)
        normalized = NormalizedSecurityEvent(
            event_id=evt_id,
            tenant_id=tenant_id,
            sensor_id=payload.sensor_id,
            timestamp=ts_formatted,
            source_ip=raw_evt.source_ip,
            destination_ip=raw_evt.destination_ip,
            source_port=raw_evt.source_port or 0,
            destination_port=raw_evt.destination_port or 0,
            protocol=raw_evt.protocol or "TCP",
            event_type=raw_evt.event_type or "connection",
            detection_source=raw_evt.detection_source or "sensor",
            severity=raw_evt.severity or "INFO",
            evidence=raw_evt.evidence or {},
            ingestion_time=now_iso
        )

        # Publish to EventBus for Layer 4 Correlation Engine
        try:
            await event_bus.publish(normalized)
        except Exception as bus_err:
            logger.warning(f"[EventsAPI] Error publishing event {evt_id} to event_bus: {bus_err}")

        # Prepare database document
        evt_doc = normalized.model_dump()
        evt_doc["created_at"] = time.time()
        new_event_docs.append(evt_doc)

    # Persist accepted events
    for doc in new_event_docs:
        try:
            await events_repo.create(doc)
            # If the event represents a detected alert or threat, also index in threats collection
            if doc.get("severity") in ["MEDIUM", "HIGH", "CRITICAL"] or doc.get("event_type") in ["alert", "anomaly"]:
                await threats_repo.create({
                    "event_id": doc["event_id"],
                    "tenant_id": doc["tenant_id"],
                    "timestamp": time.time(),
                    "timestamp_iso": doc["timestamp"],
                    "src_ip": doc["source_ip"],
                    "dst_ip": doc["destination_ip"],
                    "src_port": doc["source_port"],
                    "dst_port": doc["destination_port"],
                    "protocol": doc["protocol"],
                    "prediction": doc.get("evidence", {}).get("alert_name", f"{doc['detection_source'].upper()} {doc['event_type'].upper()}"),
                    "severity": doc["severity"].lower(),
                    "confidence": float(doc.get("evidence", {}).get("confidence", 0.85)),
                    "detection_source": doc["detection_source"]
                })
        except Exception as db_err:
            logger.error(f"[EventsAPI] Database insert error for event: {db_err}")

    # Record idempotency keys in persistent store
    await idempotency_repo.create({"key": cached_batch_key, "tenant_id": tenant_id, "timestamp": time.time()})
    _IDEMPOTENCY_CACHE.add(cached_batch_key)

    for eid in accepted_event_ids:
        await idempotency_repo.create({"key": f"evt:{tenant_id}:{eid}", "tenant_id": tenant_id, "timestamp": time.time()})

    logger.info(
        f"[EventsAPI] Ingested batch '{batch_id}' from sensor '{payload.sensor_id}' "
        f"(Accepted: {len(accepted_event_ids)}, Duplicates: {len(duplicate_event_ids)})"
    )

    return BatchIngestResponse(
        status="acknowledged",
        batch_id=batch_id,
        sensor_id=payload.sensor_id,
        accepted_count=len(accepted_event_ids),
        duplicate_count=len(duplicate_event_ids),
        accepted_event_ids=accepted_event_ids,
        duplicate_event_ids=duplicate_event_ids,
        timestamp=now_iso,
        message=f"Batch processed. {len(accepted_event_ids)} accepted, {len(duplicate_event_ids)} duplicates ignored."
    )


# --- Event Retrieval Endpoints (B. Dashboard -> Backend) ---

@router.get("", dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def list_events(
    req: Request,
    limit: int = 50,
    offset: int = 0,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    sensor_id: Optional[str] = None
):
    """
    Retrieves events for the SOC dashboard and analysts.
    Strictly scoped to the caller's organization.
    """
    try:
        tenant_id = _extract_authenticated_tenant(req)
        role = get_request_role(req)

        filter_q: Dict[str, Any] = {}
        if role != Role.ADMIN or tenant_id != "global":
            filter_q["tenant_id"] = tenant_id

        if source_ip:
            filter_q["source_ip"] = source_ip.strip()
        if destination_ip:
            filter_q["destination_ip"] = destination_ip.strip()
        if protocol:
            filter_q["protocol"] = protocol.strip().upper()
        if event_type:
            filter_q["event_type"] = event_type.strip().lower()
        if severity:
            filter_q["severity"] = severity.strip().upper()
        if sensor_id:
            filter_q["sensor_id"] = sensor_id.strip()

        bounded_limit = min(max(1, limit), 200)
        docs = await events_repo.list(
            filter_query=filter_q,
            limit=bounded_limit,
            skip=offset,
            sort_by=[("timestamp", -1)]
        )

        return docs
    except Exception as e:
        logger.error(f"[EventsAPI] Failed to retrieve events: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve events")


@router.get("/{event_id}", dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def get_event_detail(event_id: str, req: Request):
    """Retrieves single event details with tenant verification."""
    try:
        tenant_id = _extract_authenticated_tenant(req)
        role = get_request_role(req)

        filter_q = {"event_id": event_id}
        if role != Role.ADMIN or tenant_id != "global":
            filter_q["tenant_id"] = tenant_id

        docs = await events_repo.list(filter_query=filter_q, limit=1)
        if not docs:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Event '{event_id}' not found")

        return docs[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[EventsAPI] Failed to get event {event_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve event detail")

