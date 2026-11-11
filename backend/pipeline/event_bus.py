import asyncio
import time
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
        self._is_closing = False

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
        If the bus is shutting down (closing state), immediately rejects publication.
        If active pending tasks reach max_queue_size, waits up to timeout for capacity;
        if capacity is not available within timeout, applies backpressure and drops event.
        Guarantees atomic queue-limit verification and task enrollment under lock.
        Returns True if dispatched, False if rejected due to backpressure or closing state.
        """
        if self._is_closing:
            logger.warning(f"[SecurityEventBus] Bus is closing. Rejected publication for event {getattr(event, 'event_id', '?')}.")
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

        # Atomic backpressure limit check and task enrollment under lock with timeout
        start_time = time.time()
        while True:
            async with self._lock:
                if self._is_closing:
                    return False
                if len(self._active_tasks) < self.max_queue_size:
                    self._recent_events.append(event)
                    try:
                        task = asyncio.create_task(_bounded_dispatch(event))
                        self._active_tasks.add(task)
                        task.add_done_callback(self._active_tasks.discard)
                        return True
                    except RuntimeError as rt_err:
                        logger.debug(f"[SecurityEventBus] Direct fallback dispatch: {rt_err}")
                        return False

            # Queue at capacity: check if backpressure wait timeout exceeded
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                async with self._lock:
                    self._dropped_count += 1
                    logger.warning(
                        f"[SecurityEventBus] Backpressure limit reached ({self.max_queue_size} in-flight tasks). "
                        f"Timeout ({timeout}s) exceeded. Dropped event {getattr(event, 'event_id', '?')}. "
                        f"Total dropped: {self._dropped_count}"
                    )
                    return False
            await asyncio.sleep(min(0.01, timeout))

    async def drain(self, timeout: float = 5.0):
        """Awaits completion of all currently in-flight dispatch tasks."""
        tasks_to_wait = list(self._active_tasks)
        if tasks_to_wait:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks_to_wait, return_exceptions=True),
                    timeout=timeout
                )
            except (asyncio.TimeoutError, TimeoutError):
                pass

    async def shutdown(self, drain_timeout: float = 5.0):
        """
        Gracefully shuts down event bus:
        1. Atomically transitions to closing state under lock to reject new incoming publications.
        2. Awaits completion of existing in-flight dispatch tasks up to drain_timeout.
        3. Cancels any remaining unfinished tasks that exceeded timeout.
        """
        async with self._lock:
            self._is_closing = True

        # 1. Attempt graceful drain before forced cancellation
        if self._active_tasks:
            try:
                await self.drain(timeout=drain_timeout)
            except Exception as drain_err:
                logger.debug(f"[SecurityEventBus] Drain encountered exception during shutdown: {drain_err}")

        # 2. Cancel any remaining unfinished tasks that exceeded timeout
        remaining = list(self._active_tasks)
        for task in remaining:
            if not task.done():
                task.cancel()
        if remaining:
            await asyncio.gather(*remaining, return_exceptions=True)
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

