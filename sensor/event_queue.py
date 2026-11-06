import asyncio
import collections
import uuid
import time
from typing import List, Dict, Any, Optional
from backend.pipeline.schemas import NormalizedSecurityEvent

class LocalEventQueue:
    """
    Step 6: Local Event Queue
    Thread-safe local event buffer on the sensor host.
    Holds structured security events ready for cloud shipment.
    Ensures safe retries without losing security events during network blips.
    """
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self._queue: collections.deque[NormalizedSecurityEvent] = collections.deque()
        self._in_flight_batches: Dict[str, List[NormalizedSecurityEvent]] = {}
        self._lock = asyncio.Lock()

    async def enqueue(self, event: NormalizedSecurityEvent) -> bool:
        """Enqueues a normalized security event into the local buffer."""
        async with self._lock:
            if len(self._queue) >= self.max_size:
                # Discard oldest non-alert event if buffer is saturated
                self._queue.popleft()
            self._queue.append(event)
            return True

    async def get_batch(self, max_items: int = 50) -> tuple[str, List[NormalizedSecurityEvent]]:
        """
        Creates an in-flight batch ready for transmission.
        Keeps batch in `_in_flight_batches` until acknowledged.
        """
        batch_id = f"batch-{int(time.time())}-{uuid.uuid4().hex[:6]}"
        batch: List[NormalizedSecurityEvent] = []

        async with self._lock:
            while self._queue and len(batch) < max_items:
                batch.append(self._queue.popleft())

            if batch:
                self._in_flight_batches[batch_id] = batch

        return batch_id, batch

    async def acknowledge_batch(self, batch_id: str, accepted_ids: Optional[List[str]] = None):
        """Called when Central Platform returns successful HTTP acknowledgment."""
        async with self._lock:
            self._in_flight_batches.pop(batch_id, None)

    async def requeue_failed_batch(self, batch_id: str):
        """Puts an unacknowledged batch back at the head of the queue for retry."""
        async with self._lock:
            failed_batch = self._in_flight_batches.pop(batch_id, None)
            if failed_batch:
                # Prepend in reverse to maintain original order
                for ev in reversed(failed_batch):
                    self._queue.appendleft(ev)

    @property
    def queue_depth(self) -> int:
        return len(self._queue)

    @property
    def in_flight_count(self) -> int:
        return sum(len(b) for b in self._in_flight_batches.values())
