import httpx
import time
from typing import Dict, Any, List, Optional
from backend.utils.logger import get_logger
from backend.pipeline.schemas import NormalizedSecurityEvent
from sensor.event_queue import LocalEventQueue

logger = get_logger(__name__)

class SecureCloudShipper:
    """
    Step 7: Secure Cloud Ingestion Client
    Batches structured security events and transmits them to the Central NetrIQ Platform
    via authenticated HTTPS POST /api/v1/events/batch.
    Handles acknowledgments, retries, and sensor heartbeat reports.
    """
    def __init__(
        self,
        central_url: str,
        sensor_id: str,
        api_key: str,
        event_queue: LocalEventQueue
    ):
        self.central_url = central_url.rstrip("/")
        self.sensor_id = sensor_id
        self.api_key = api_key
        self.event_queue = event_queue
        self._http_client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                base_url=self.central_url,
                timeout=10.0,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "X-Sensor-Key": self.api_key
                }
            )
        return self._http_client

    async def flush_once(self, max_items: int = 50) -> Dict[str, Any]:
        """Dequeues a batch and transmits it to the central cloud platform."""
        batch_id, events = await self.event_queue.get_batch(max_items=max_items)
        if not events:
            return {"status": "idle", "sent_count": 0}

        payload = {
            "sensor_id": self.sensor_id,
            "batch_id": batch_id,
            "events": [
                {
                    "event_id": e.event_id,
                    "timestamp": e.timestamp,
                    "source_ip": e.source_ip,
                    "destination_ip": e.destination_ip,
                    "source_port": e.source_port,
                    "destination_port": e.destination_port,
                    "protocol": e.protocol,
                    "event_type": e.event_type,
                    "detection_source": e.detection_source,
                    "severity": e.severity,
                    "evidence": e.evidence
                }
                for e in events
            ]
        }

        client = await self._get_client()
        try:
            resp = await client.post("/api/v1/events/batch", json=payload)
            if resp.status_code == 200:
                data = resp.json()
                await self.event_queue.acknowledge_batch(batch_id, data.get("accepted_event_ids"))
                logger.info(
                    f"[CloudShipper] Successfully ingested batch {batch_id}: "
                    f"{data.get('accepted_count')} accepted, {data.get('duplicate_count')} duplicate"
                )
                return data
            else:
                logger.warning(f"[CloudShipper] Cloud rejected batch {batch_id} (HTTP {resp.status_code}): {resp.text}")
                await self.event_queue.requeue_failed_batch(batch_id)
                return {"status": "error", "code": resp.status_code, "detail": resp.text}
        except Exception as net_err:
            logger.error(f"[CloudShipper] Network error transmitting batch {batch_id}: {net_err}")
            await self.event_queue.requeue_failed_batch(batch_id)
            return {"status": "network_error", "detail": str(net_err)}

    async def send_heartbeat(
        self,
        cpu_pct: float = 12.5,
        ram_mb: float = 240.0,
        kernel_drops: int = 0,
        packets_processed: int = 1000,
        uptime_seconds: float = 3600.0
    ) -> Dict[str, Any]:
        """Reports sensor operational health and packet drop telemetry to central management."""
        client = await self._get_client()
        try:
            resp = await client.post("/api/v1/sensors/heartbeat", json={
                "sensor_id": self.sensor_id,
                "cpu_usage_pct": cpu_pct,
                "memory_usage_mb": ram_mb,
                "kernel_drops_count": kernel_drops,
                "packets_processed": packets_processed,
                "uptime_seconds": uptime_seconds
            })
            return resp.json() if resp.status_code == 200 else {"status": "failed", "code": resp.status_code}
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    async def close(self):
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
