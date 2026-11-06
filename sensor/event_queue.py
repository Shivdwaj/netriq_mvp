import asyncio
import collections
import json
import os
import sqlite3
import time
import uuid
from typing import List, Dict, Any, Optional, Tuple

from backend.pipeline.schemas import NormalizedSecurityEvent
from backend.utils.logger import get_logger

logger = get_logger(__name__)

class LocalEventQueue:
    """
    Step 6: Local Event Queue with Optional Persistent Disk Spooling
    Thread-safe local event buffer on the sensor host.
    Holds structured security events ready for cloud shipment.
    Ensures safe retries without losing security events during network blips or host reboots.

    Features:
    - In-memory deque for ultra-low latency event queuing.
    - Optional SQLite WAL-mode disk spool for offline persistence across restarts.
    - Crash recovery: unacknowledged in-flight batches from previous runs are recovered to 'queued'.
    - FIFO retention bounding: disk spool and memory queue prune oldest events when full.
    """
    def __init__(
        self,
        max_size: int = 10000,
        disk_spool_path: Optional[str] = None,
        max_disk_size: int = 50000
    ):
        self.max_size = max_size
        self.max_disk_size = max_disk_size
        self.disk_spool_path = disk_spool_path or os.getenv("NETRIQ_SENSOR_SPOOL_PATH")
        
        self._queue: collections.deque[NormalizedSecurityEvent] = collections.deque()
        self._in_flight_batches: Dict[str, List[NormalizedSecurityEvent]] = {}
        self._lock = asyncio.Lock()
        self._db_conn: Optional[sqlite3.Connection] = None

        if self.disk_spool_path:
            self._init_disk_spool()

    def _init_disk_spool(self):
        """Initializes SQLite disk spool with WAL mode and recovers orphaned events."""
        try:
            spool_dir = os.path.dirname(os.path.abspath(self.disk_spool_path))
            if spool_dir and not os.path.exists(spool_dir):
                os.makedirs(spool_dir, exist_ok=True)

            self._db_conn = sqlite3.connect(
                self.disk_spool_path,
                check_same_thread=False,
                timeout=10.0
            )
            self._db_conn.execute("PRAGMA journal_mode=WAL;")
            self._db_conn.execute("PRAGMA synchronous=NORMAL;")
            
            with self._db_conn:
                self._db_conn.execute("""
                    CREATE TABLE IF NOT EXISTS event_spool (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT UNIQUE,
                        batch_id TEXT,
                        status TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        created_at REAL NOT NULL
                    )
                """)
                self._db_conn.execute("CREATE INDEX IF NOT EXISTS idx_spool_status ON event_spool(status);")
                self._db_conn.execute("CREATE INDEX IF NOT EXISTS idx_spool_batch ON event_spool(batch_id);")

                # Crash recovery: reset any in_flight events left from abnormal termination
                recovered = self._db_conn.execute(
                    "UPDATE event_spool SET status = 'queued', batch_id = NULL WHERE status = 'in_flight'"
                ).rowcount
                if recovered > 0:
                    logger.info(f"[EventQueue] Recovered {recovered} in-flight events from previous run into queue.")

                # Pre-load queued events into in-memory queue up to max_size
                cursor = self._db_conn.execute(
                    "SELECT payload FROM event_spool WHERE status = 'queued' ORDER BY id ASC LIMIT ?",
                    (self.max_size,)
                )
                rows = cursor.fetchall()
                for row in rows:
                    try:
                        event = NormalizedSecurityEvent.model_validate_json(row[0])
                        self._queue.append(event)
                    except Exception as parse_err:
                        logger.warning(f"[EventQueue] Failed to parse spooled event: {parse_err}")

                logger.info(
                    f"[EventQueue] Initialized persistent disk spool at '{self.disk_spool_path}' "
                    f"with {len(self._queue)} pending events loaded into memory."
                )
        except Exception as e:
            logger.error(f"[EventQueue] Failed to initialize disk spool at '{self.disk_spool_path}': {e}")
            self._db_conn = None

    async def enqueue(self, event: NormalizedSecurityEvent) -> bool:
        """Enqueues a normalized security event into the local buffer and disk spool."""
        async with self._lock:
            # 1. Persist to disk spool if enabled
            if self._db_conn:
                try:
                    payload = event.model_dump_json()
                    now = time.time()
                    with self._db_conn:
                        self._db_conn.execute(
                            "INSERT OR IGNORE INTO event_spool (event_id, batch_id, status, payload, created_at) "
                            "VALUES (?, NULL, 'queued', ?, ?)",
                            (event.event_id, payload, now)
                        )
                        # Bounded spool retention
                        count_row = self._db_conn.execute("SELECT COUNT(*) FROM event_spool").fetchone()
                        if count_row and count_row[0] > self.max_disk_size:
                            excess = count_row[0] - self.max_disk_size
                            self._db_conn.execute(
                                "DELETE FROM event_spool WHERE id IN "
                                "(SELECT id FROM event_spool WHERE status = 'queued' ORDER BY id ASC LIMIT ?)",
                                (excess,)
                            )
                except Exception as disk_err:
                    logger.warning(f"[EventQueue] Disk spool write failed for event {event.event_id}: {disk_err}")

            # 2. Add to in-memory queue
            if len(self._queue) >= self.max_size:
                # Discard oldest event if memory buffer is saturated
                self._queue.popleft()
            self._queue.append(event)
            return True

    async def get_batch(self, max_items: int = 50) -> Tuple[str, List[NormalizedSecurityEvent]]:
        """
        Creates an in-flight batch ready for transmission.
        Marks batch in SQLite spool as 'in_flight' and retains in `_in_flight_batches` until acknowledged.
        """
        batch_id = f"batch-{int(time.time())}-{uuid.uuid4().hex[:6]}"
        batch: List[NormalizedSecurityEvent] = []

        async with self._lock:
            while self._queue and len(batch) < max_items:
                batch.append(self._queue.popleft())

            if batch:
                self._in_flight_batches[batch_id] = batch

                # Update status in disk spool
                if self._db_conn:
                    try:
                        event_ids = [e.event_id for e in batch]
                        placeholders = ",".join("?" for _ in event_ids)
                        with self._db_conn:
                            self._db_conn.execute(
                                f"UPDATE event_spool SET status = 'in_flight', batch_id = ? "
                                f"WHERE event_id IN ({placeholders})",
                                [batch_id] + event_ids
                            )
                    except Exception as disk_err:
                        logger.warning(f"[EventQueue] Failed to mark batch {batch_id} in-flight on disk: {disk_err}")

        return batch_id, batch

    async def acknowledge_batch(self, batch_id: str, accepted_ids: Optional[List[str]] = None):
        """Called when Central Platform returns successful HTTP acknowledgment."""
        async with self._lock:
            self._in_flight_batches.pop(batch_id, None)

            # Delete acknowledged batch from disk spool
            if self._db_conn:
                try:
                    with self._db_conn:
                        self._db_conn.execute(
                            "DELETE FROM event_spool WHERE batch_id = ?",
                            (batch_id,)
                        )
                except Exception as disk_err:
                    logger.warning(f"[EventQueue] Failed to delete acknowledged batch {batch_id} from disk: {disk_err}")

    async def requeue_failed_batch(self, batch_id: str):
        """Puts an unacknowledged batch back at the head of the queue for retry."""
        async with self._lock:
            failed_batch = self._in_flight_batches.pop(batch_id, None)
            if failed_batch:
                # Prepend in reverse to maintain original chronological order
                for ev in reversed(failed_batch):
                    self._queue.appendleft(ev)

                # Reset status in disk spool
                if self._db_conn:
                    try:
                        with self._db_conn:
                            self._db_conn.execute(
                                "UPDATE event_spool SET status = 'queued', batch_id = NULL WHERE batch_id = ?",
                                (batch_id,)
                            )
                    except Exception as disk_err:
                        logger.warning(f"[EventQueue] Failed to requeue batch {batch_id} on disk: {disk_err}")

    @property
    def queue_depth(self) -> int:
        return len(self._queue)

    @property
    def in_flight_count(self) -> int:
        return sum(len(b) for b in self._in_flight_batches.values())

    def disk_spool_depth(self) -> int:
        """Returns total records currently preserved on disk spool."""
        if not self._db_conn:
            return 0
        try:
            row = self._db_conn.execute("SELECT COUNT(*) FROM event_spool WHERE status = 'queued'").fetchone()
            return row[0] if row else 0
        except Exception:
            return 0

    def close(self):
        """Closes SQLite database connection cleanly."""
        if self._db_conn:
            try:
                self._db_conn.close()
            except Exception:
                pass
            self._db_conn = None
