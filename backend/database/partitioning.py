"""
partitioning.py
Time-based partitioning and retention policy management for high-volume NetrIQ entities:
- network_events: partitioned by year-month (e.g., network_events_2026_11)
- RetentionPolicyManager: automated pruning and lifecycle enforcement according to tenant policy
"""

import time
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from backend.database.database import DatabaseManager
from backend.utils.logger import get_logger

logger = get_logger(__name__)

class TimePartitionManager:
    """
    Manages time-based collection partitioning for high-volume network telemetry.
    Ensures queries over specific time ranges only hit relevant monthly collections.
    """
    BASE_COLLECTION = "network_events"

    @classmethod
    def get_partition_name(cls, timestamp: Optional[float] = None) -> str:
        """
        Computes the target partition collection name for a given epoch timestamp.
        Format: network_events_YYYY_MM (e.g. network_events_2026_11)
        """
        ts = timestamp if timestamp is not None else time.time()
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return f"{cls.BASE_COLLECTION}_{dt.year}_{dt.month:02d}"

    @classmethod
    def get_partition_range_names(cls, start_time: float, end_time: float) -> List[str]:
        """
        Returns all collection partition names spanning between start_time and end_time.
        """
        dt_start = datetime.fromtimestamp(start_time, tz=timezone.utc).replace(day=1, hour=0, minute=0, second=0)
        dt_end = datetime.fromtimestamp(end_time, tz=timezone.utc).replace(day=1, hour=0, minute=0, second=0)

        partitions = []
        curr = dt_start
        while curr <= dt_end:
            partitions.append(f"{cls.BASE_COLLECTION}_{curr.year}_{curr.month:02d}")
            # Move to first day of next month
            if curr.month == 12:
                curr = curr.replace(year=curr.year + 1, month=1)
            else:
                curr = curr.replace(month=curr.month + 1)
        return partitions


class RetentionPolicyManager:
    """
    Automated data retention and lifecycle pruning engine.
    Prunes expired events, alerts, sensor health telemetry, and evidence records
    based on tenant configuration and system defaults.
    """

    @classmethod
    async def prune_expired_records(
        cls,
        tenant_id: str,
        event_retention_days: int = 30,
        sensor_health_retention_days: int = 7,
        evidence_retention_days: int = 14
    ) -> Dict[str, int]:
        """
        Prunes documents whose age exceeds the specified retention window for a given tenant.
        Returns a summary dictionary of deleted record counts.
        """
        db = DatabaseManager.get_db()
        now = time.time()

        events_cutoff = now - (event_retention_days * 86400)
        health_cutoff = now - (sensor_health_retention_days * 86400)
        evidence_cutoff = now  # Evidence has explicit expires_at timestamp

        tenant_filter = {} if tenant_id == "global" else {"tenant_id": tenant_id}
        counts = {
            "network_events_pruned": 0,
            "sensor_health_pruned": 0,
            "evidence_pruned": 0
        }

        try:
            # 1. Prune network_events
            ev_query = dict(tenant_filter)
            ev_query["created_at"] = {"$lt": events_cutoff}
            for coll_name in ["network_events", "events"]:
                try:
                    res = await db[coll_name].delete_many(ev_query)
                    counts["network_events_pruned"] += getattr(res, "deleted_count", 0)
                except Exception:
                    pass

            # 2. Prune sensor_health
            sh_query = dict(tenant_filter)
            sh_query["timestamp"] = {"$lt": health_cutoff}
            try:
                res = await db["sensor_health"].delete_many(sh_query)
                counts["sensor_health_pruned"] += getattr(res, "deleted_count", 0)
            except Exception:
                pass

            # 3. Prune expired evidence (and remove file from disk)
            evi_query = dict(tenant_filter)
            evi_query["expires_at"] = {"$lt": evidence_cutoff}
            try:
                from backend.services.evidence_service import evidence_service
                cursor = db["evidence"].find(evi_query)
                if hasattr(cursor, "to_list"):
                    expired_docs = await cursor.to_list(length=1000)
                elif hasattr(cursor, "__iter__"):
                    expired_docs = list(cursor)
                else:
                    expired_docs = await cursor

                for doc in expired_docs:
                    fp = doc.get("file_path")
                    if fp:
                        try:
                            full_fp = evidence_service.storage_dir.parent / fp
                            if full_fp.exists():
                                full_fp.unlink()
                        except Exception:
                            pass

                res = await db["evidence"].delete_many(evi_query)
                counts["evidence_pruned"] += getattr(res, "deleted_count", 0)
            except Exception:
                pass

            logger.info(f"[RetentionPolicyManager] Retention cleanup for {tenant_id}: {counts}")
        except Exception as e:
            logger.error(f"[RetentionPolicyManager] Error enforcing retention policy: {e}")

        return counts
