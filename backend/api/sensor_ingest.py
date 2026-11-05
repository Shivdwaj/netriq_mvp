from typing import List, Dict, Any, Union
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from backend.auth.roles import Capabilities
from backend.auth.permissions import require_permission
from backend.utils.logger import get_logger
from backend.pipeline import event_bus
from backend.adapters import suricata_adapter, zeek_adapter

logger = get_logger(__name__)
router = APIRouter(prefix="/sensors", tags=["sensors"])

class IngestResponse(BaseModel):
    status: str
    events_ingested: int
    events_published: int

@router.post("/suricata/eve", response_model=IngestResponse)
async def ingest_suricata_eve(payload: Union[Dict[str, Any], List[Dict[str, Any]]]):
    """
    Ingests Suricata EVE JSON alerts, anomalies, or protocol events.
    Normalizes into NetrIQ security events and streams to the Correlation Engine.
    """
    try:
        records = [payload] if isinstance(payload, dict) else payload
        published = 0
        for rec in records:
            event = suricata_adapter.transform(rec)
            if event:
                await event_bus.publish(event)
                published += 1

        return IngestResponse(
            status="success",
            events_ingested=len(records),
            events_published=published
        )
    except Exception as e:
        logger.error(f"[SensorIngest API] Error ingesting Suricata EVE: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to ingest Suricata EVE")

@router.post("/zeek/conn", response_model=IngestResponse)
async def ingest_zeek_conn(payload: Union[Dict[str, Any], List[Dict[str, Any]]]):
    """
    Ingests Zeek conn.log records describing connection state, duration, and session metrics.
    """
    try:
        records = [payload] if isinstance(payload, dict) else payload
        published = 0
        for rec in records:
            event = zeek_adapter.transform(rec)
            if event:
                await event_bus.publish(event)
                published += 1

        return IngestResponse(
            status="success",
            events_ingested=len(records),
            events_published=published
        )
    except Exception as e:
        logger.error(f"[SensorIngest API] Error ingesting Zeek conn: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to ingest Zeek conn logs")

@router.post("/zeek/dns", response_model=IngestResponse)
async def ingest_zeek_dns(payload: Union[Dict[str, Any], List[Dict[str, Any]]]):
    """
    Ingests Zeek dns.log records describing domain queries and IP resolutions.
    """
    try:
        records = [payload] if isinstance(payload, dict) else payload
        published = 0
        for rec in records:
            event = zeek_ingestor.parse_dns_record(rec)
            if event:
                await event_bus.publish(event)
                published += 1

        return IngestResponse(
            status="success",
            events_ingested=len(records),
            events_published=published
        )
    except Exception as e:
        logger.error(f"[SensorIngest API] Error ingesting Zeek DNS: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to ingest Zeek DNS logs")

