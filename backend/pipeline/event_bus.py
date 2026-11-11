import asyncio
import collections
from typing import List, Callable, Awaitable, Deque, Optional, Set
from backend.utils.logger import get_logger
from backend.pipeline.schemas import NormalizedSecurityEvent

logger = get_logger(__name__)

class SecurityEventBus:
    """
    Asynchronous event bus.
    Receives normalized security events from Layer 2 (Data Processing)
    and dispatches them to downstream consumers (Layer 4 Correlation, Storage, WebSockets).
    Implements bounded concurrency via Semaphore, active task tracking, and backpressure
    to prevent memory exhaustion or unbounded task explosion during high-throughput packet bursts.
    """

    def __init__(self, history_limit: int = 500, max_concurrency: int = 50, max_queue_size: int = 5000):
        self._subscribers: List[Callable[[NormalizedSecurityEvent], Awaitable[None]]] = []
        self._recent_events: Deque[NormalizedSecurityEvent] = collections.deque(maxlen=history_limit)
        self._lock = asyncio.Lock()
        self.max_concurrency = max_concurrency
        self.max_queue_size = max_queue_size
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._active_tasks: Set[asyncio.Task] = set()
        self._dropped_count = 0

    def _get_semaphore(self) -> asyncio.Semaphore:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrency)
        return self._semaphore

    def subscribe(self, callback: Callable[[NormalizedSecurityEvent], Awaitable[None]]):
        """Registers an asynchronous consumer callback for all normalized events."""
        if callback not in self._subscribers:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[NormalizedSecurityEvent], Awaitable[None]]):
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    async def publish(self, event: NormalizedSecurityEvent, timeout: float = 2.0) -> bool:
        """
        Publishes an event to all subscribers with bounded concurrency and backpressure.
        If active pending tasks reach max_queue_size, applies backpressure and drops event.
        Returns True if dispatched, False if rejected due to backpressure.
        """
        async with self._lock:
            self._recent_events.append(event)

        # Backpressure limit check
        if len(self._active_tasks) >= self.max_queue_size:
            self._dropped_count += 1
            logger.warning(
                f"[SecurityEventBus] Backpressure limit reached ({self.max_queue_size} in-flight tasks). "
                f"Dropped event {getattr(event, 'event_id', '?')}. Total dropped: {self._dropped_count}"
            )
            return False

        sem = self._get_semaphore()

        async def _bounded_dispatch(ev: NormalizedSecurityEvent):
            async with sem:
                for callback in list(self._subscribers):
                    try:
                        await callback(ev)
                    except Exception as e:
                        logger.warning(
                            f"[SecurityEventBus] Subscriber {getattr(callback, '__name__', 'cb')} "
                            f"failed on event {getattr(ev, 'event_id', '?')}: {e}"
                        )

        try:
            task = asyncio.create_task(_bounded_dispatch(event))
            self._active_tasks.add(task)
            task.add_done_callback(self._active_tasks.discard)
            return True
        except RuntimeError as rt_err:
            # Fallback if called outside active event loop
            logger.debug(f"[SecurityEventBus] Direct fallback dispatch: {rt_err}")
            return False

    async def drain(self, timeout: float = 5.0):
        """Awaits completion of all currently in-flight dispatch tasks."""
        if self._active_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*list(self._active_tasks), return_exceptions=True),
                    timeout=timeout
                )
            except (asyncio.TimeoutError, TimeoutError):
                pass

    async def shutdown(self):
        """Cancels all active in-flight dispatch tasks on server shutdown."""
        for task in list(self._active_tasks):
            task.cancel()
        if self._active_tasks:
            await asyncio.gather(*list(self._active_tasks), return_exceptions=True)
        self._active_tasks.clear()

    @property
    def queue_depth(self) -> int:
        return len(self._active_tasks)

    @property
    def dropped_count(self) -> int:
        return self._dropped_count

    def get_recent_events(self, limit: int = 100) -> List[NormalizedSecurityEvent]:
        """Retrieves recent normalized events for SOC analysts and management APIs."""
        events_list = list(self._recent_events)
        return events_list[-limit:]

event_bus = SecurityEventBus()

