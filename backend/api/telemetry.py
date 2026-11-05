import time
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.auth.roles import Capabilities
from backend.auth.permissions import require_permission
from backend.utils.logger import get_logger
from backend.pipeline import (
    normalizer,
    event_bus,
    identity_resolver,
    NormalizedSecurityEvent,
    EventType,
    EventSource
)
from backend.database.device_behavior_repo import device_behaviors_repo
from backend.services.behavior_service import behavior_engine

logger = get_logger(__name__)
router = APIRouter(prefix="/telemetry", tags=["telemetry"])

class EndpointTelemetryReq(BaseModel):
    mac: str
    ip: str
    hostname: str
    os: Optional[str] = None
    logged_in_user: Optional[str] = None
    is_elevated: Optional[bool] = False
    active_processes_count: Optional[int] = 0
    sample_processes: Optional[List[str]] = Field(default_factory=list)
    processes: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    connections: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    auth_events: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    suspicious_processes: Optional[List[str]] = Field(default_factory=list)
    timestamp: Optional[float] = None

class NetworkFlowTelemetryReq(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = 0
    dst_port: Optional[int] = 0
    protocol: Optional[str] = "TCP"
    length: Optional[int] = 0
    flags: Optional[List[str]] = Field(default_factory=list)
    dns_query: Optional[str] = None
    sensor_id: Optional[str] = "span-tap-01"
    timestamp: Optional[float] = None

@router.post("/endpoint")
async def ingest_endpoint_telemetry(payload: EndpointTelemetryReq):
    """
    Layer 1 Data Acquisition -> Layer 2 Data Processing.
    Ingests raw endpoint telemetry, normalizes into structured security events,
    deduplicates, attaches device identity, and publishes to the SecurityEventBus.
    """
    try:
        raw_dict = payload.model_dump()
        mac = payload.mac.upper()

        # 1. Update/Ensure device behavior baseline exists in MongoDB
        profile = await behavior_engine.get_or_create_profile(
            ip=payload.ip,
            mac=mac,
            hostname=payload.hostname
        )

        now_ts = payload.timestamp or time.time()
        agent_fields = {
            "last_seen": now_ts,
            "current_ip": payload.ip,
            "hostname": payload.hostname,
            "os_environment": payload.os,
            "logged_in_user": payload.logged_in_user,
            "active_processes_count": payload.active_processes_count,
            "sample_processes": payload.sample_processes or [],
            "suspicious_processes": payload.suspicious_processes or [],
            "agent_active": True,
            "last_agent_heartbeat": now_ts
        }

        # 2. Decompose and normalize endpoint events
        events = normalizer.normalize_endpoint_telemetry(raw_dict)

        # 3. Publish to Event Bus for downstream consumers (Correlation Engine, Storage, WebSockets)
        for ev in events:
            await event_bus.publish(ev)

        # 4. If agent reported suspicious hacking tool executions
        if payload.suspicious_processes:
            proc_list = ", ".join(payload.suspicious_processes)
            violations = [f"Blacklisted process running on host: {proc_list}"]
            await behavior_engine._handle_anomaly(
                profile=profile,
                src_ip=payload.ip,
                mac=mac,
                hostname=payload.hostname,
                dst_ip="localhost",
                dst_port=0,
                violations=violations
            )

        # 5. Update MongoDB profile
        await device_behaviors_repo.collection.update_one(
            {"mac": mac},
            {"$set": agent_fields}
        )

        is_quar = (profile.get("status") == "QUARANTINED")
        quar_reason = profile.get("quarantine_reason", "Quarantined by SOC Admin")

        return {
            "status": "success",
            "events_normalized": len(events),
            "is_quarantined": is_quar,
            "quarantine_reason": quar_reason if is_quar else None,
            "server_time": time.time()
        }
    except Exception as e:
        logger.error(f"[Telemetry API] Failed to ingest endpoint telemetry from {payload.mac}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process endpoint telemetry"
        )

@router.post("/network-flow")
async def ingest_network_flow_telemetry(payload: NetworkFlowTelemetryReq):
    """
    Layer 1 Data Acquisition -> Layer 2 Data Processing.
    Ingests external network packets or flow summaries from SPAN mirrors or network TAPs.
    """
    try:
        raw_dict = payload.model_dump()
        event = normalizer.normalize_network_packet(raw_dict, source=EventSource.EXTERNAL_TAP)
        if event:
            await event_bus.publish(event)
            return {"status": "success", "event_id": event.event_id, "deduplicated": False}
        return {"status": "dropped", "reason": "duplicate_or_invalid", "deduplicated": True}
    except Exception as e:
        logger.error(f"[Telemetry API] Failed to ingest network flow: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process network flow"
        )

@router.get("/events", dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def get_recent_normalized_events(
    limit: int = Query(default=50, ge=1, le=200),
    event_type: Optional[str] = None
):
    """
    Returns recent normalized security events from the in-memory circular buffer.
    """
    events = event_bus.get_recent_events(limit=limit)
    if event_type:
        events = [e for e in events if e.event_type.value == event_type]
    return [e.model_dump() for e in events]

@router.get("/sensors", dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def list_sensors_and_agents():
    """
    Layer 5 Admin Dashboard API:
    Lists active network sensor status and registered endpoint agents.
    """
    from backend.services.monitoring_service import monitoring_service

    # Network Sensor Status
    sensor_status = monitoring_service.get_status()

    # Endpoint Agent Status from DB
    agents = await device_behaviors_repo.list(
        filter_query={"agent_active": True},
        limit=100,
        sort_by=[("last_seen", -1)]
    )

    now = time.time()
    formatted_agents = []
    for a in agents:
        last_seen = a.get("last_seen", 0)
        is_online = (now - last_seen) < 45.0  # heartbeats every 15s; 3 intervals considered alive
        formatted_agents.append({
            "mac": a.get("mac"),
            "hostname": a.get("hostname"),
            "ip": a.get("current_ip"),
            "os": a.get("os_environment"),
            "logged_in_user": a.get("logged_in_user"),
            "status": "online" if is_online else "offline",
            "last_heartbeat": last_seen,
            "is_quarantined": a.get("status") == "QUARANTINED"
        })

    return {
        "network_sensors": [
            {
                "sensor_id": "netriq-primary-nic",
                "type": "Network SPAN/Promiscuous TAP",
                "interface": sensor_status.get("interface", "auto"),
                "status": "active" if sensor_status.get("running") else "idle",
                "packets_captured": sensor_status.get("packets_captured", 0),
                "flows_processed": sensor_status.get("flows_processed", 0)
            }
        ],
        "endpoint_agents": formatted_agents
    }

