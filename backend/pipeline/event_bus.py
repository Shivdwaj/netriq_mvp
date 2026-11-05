import asyncio
import collections
from typing import List, Callable, Awaitable, Deque
from backend.utils.logger import get_logger
from backend.pipeline.schemas import NormalizedSecurityEvent

logger = get_logger(__name__)

class SecurityEventBus:
    """
    Asynchronous event bus.
    Receives normalized security events from Layer 2 (Data Processing)
    and dispatches them to downstream consumers (Layer 4 Correlation, Storage, WebSockets).
    """

    def __init__(self, history_limit: int = 500):
        self._subscribers: List[Callable[[NormalizedSecurityEvent], Awaitable[None]]] = []
        self._recent_events: Deque[NormalizedSecurityEvent] = collections.deque(maxlen=history_limit)
        self._lock = asyncio.Lock()

    def subscribe(self, callback: Callable[[NormalizedSecurityEvent], Awaitable[None]]):
        """Registers an asynchronous consumer callback for all normalized events."""
        if callback not in self._subscribers:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[NormalizedSecurityEvent], Awaitable[None]]):
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    async def publish(self, event: NormalizedSecurityEvent):
        """Publishes an event to all subscribers and appends to the in-memory circular buffer."""
        async with self._lock:
            self._recent_events.append(event)

        for callback in self._subscribers:
            try:
                # Execute consumer asynchronously without blocking the pipeline
                asyncio.create_task(callback(event))
            except Exception as e:
                logger.warning(f"[SecurityEventBus] Subscriber failed on event {event.event_id}: {e}")

    def get_recent_events(self, limit: int = 100) -> List[NormalizedSecurityEvent]:
        """Retrieves recent normalized events for SOC analysts and management APIs."""
        events_list = list(self._recent_events)
        return events_list[-limit:]

event_bus = SecurityEventBus()

