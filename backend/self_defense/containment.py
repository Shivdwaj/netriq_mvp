"""
backend/self_defense/containment.py

Sensor Containment Manager for the Autonomous Response Controller (ARC).
Implements:
1. Staged autonomous sensor quarantine and credential revocation.
2. Idempotent containment (repeated triggers do not cause repeated state corruption).
3. Multi-tenant isolation ensuring Tenant A sensors never affect Tenant B.
4. Database persistence surviving backend restarts.
5. Sealed audit logging for all containment operations.
"""

import time
import asyncio
from typing import Dict, Any, Optional, Set, Tuple
from collections import defaultdict

from backend.utils.logger import get_logger
from backend.self_defense.schemas import (
    ContainmentStatus,
    ContainmentStage,
    ContainmentRecord,
    SecurityAlert,
    AlertSeverity,
    AlertCategory,
    get_utc_now_timestamp,
)
from backend.self_defense.audit_ledger import (
    CryptographicallySealedAuditLedger,
    audit_ledger as global_audit_ledger,
)

logger = get_logger(__name__)


class SensorContainmentManager:
    """
    Manages active sensor containment states (quarantines and revocations).
    """

    def __init__(
        self,
        sensors_repository=None,
        audit_ledger_instance: Optional[CryptographicallySealedAuditLedger] = None,
    ):
        self._repo = sensors_repository
        self._audit = audit_ledger_instance or global_audit_ledger
        self._locks: Dict[Tuple[str, str], asyncio.Lock] = defaultdict(asyncio.Lock)
        
        # In-memory containment records: (tenant_id, sensor_id) -> ContainmentRecord
        self._containment_store: Dict[Tuple[str, str], ContainmentRecord] = {}

    def _get_repo(self):
        if self._repo is not None:
            return self._repo
        from backend.database.collections import sensors_repo
        return sensors_repo

    async def is_sensor_contained(self, sensor_id: str, tenant_id: str) -> bool:
        """
        Returns True if the sensor is currently in QUARANTINED or REVOKED state.
        Checks in-memory cache first, then database persistence.
        """
        key = (tenant_id, sensor_id)
        if key in self._containment_store:
            record = self._containment_store[key]
            if record.status in (ContainmentStatus.QUARANTINED, ContainmentStatus.REVOKED):
                return True

        # Check database persistence
        repo = self._get_repo()
        try:
            filter_q = {"sensor_id": sensor_id, "tenant_id": tenant_id}
            docs = await repo.list(filter_query=filter_q, limit=1)
            if not docs and tenant_id == "global":
                docs = await repo.list(filter_query={"sensor_id": sensor_id}, limit=1)

            if docs:
                s = docs[0]
                is_active = s.get("is_active", True)
                status = s.get("status", "active")
                if not is_active or status in ("quarantined", "revoked", "deactivated", "disabled"):
                    # Cache in-memory
                    rec = ContainmentRecord(
                        tenant_id=tenant_id,
                        sensor_id=sensor_id,
                        status=ContainmentStatus.REVOKED if status == "revoked" else ContainmentStatus.QUARANTINED,
                        stage=ContainmentStage.STAGE_2_REVOKE if status == "revoked" else ContainmentStage.STAGE_1_QUARANTINE,
                        triggered_by="PERSISTED_DATABASE_STATE",
                        trigger_reason=f"Persisted status: {status}, is_active: {is_active}",
                    )
                    self._containment_store[key] = rec
                    return True
        except Exception as e:
            logger.warning(f"[SensorContainment] Failed to verify DB containment for {sensor_id}: {e}")

        return False

    async def get_containment_record(self, sensor_id: str, tenant_id: str) -> Optional[ContainmentRecord]:
        """Returns the active containment record for a sensor, if any."""
        key = (tenant_id, sensor_id)
        if key in self._containment_store:
            return self._containment_store[key]
        if await self.is_sensor_contained(sensor_id, tenant_id):
            return self._containment_store.get(key)
        return None

    async def execute_staged_containment(
        self,
        sensor_id: str,
        tenant_id: str,
        trust_score: Optional[float] = None,
        triggered_by: str = "STE_TRUST_COLLAPSE",
        trigger_reason: str = "Trust score collapsed below 0.50",
        details: Optional[Dict[str, Any]] = None,
    ) -> ContainmentRecord:
        """
        Executes Staged Autonomous Containment (Option B):
        Stage 1: Immediately quarantine incoming telemetry batches and mark sensor quarantined.
        Stage 2: Revoke API key credentials, disconnect sensor, and mark sensor revoked.
        
        Idempotent: Subsequent calls for already-contained sensors return the existing record
        without modifying or corrupting state.
        """
        key = (tenant_id, sensor_id)
        details = details or {}

        async with self._locks[key]:
            # Idempotency check: if already quarantined or revoked, do not repeat destructive mutation
            if key in self._containment_store:
                existing = self._containment_store[key]
                if existing.status in (ContainmentStatus.QUARANTINED, ContainmentStatus.REVOKED):
                    logger.info(
                        f"[SensorContainment] Sensor {sensor_id} in tenant {tenant_id} is already "
                        f"in state '{existing.status.value}'. Skipping redundant containment."
                    )
                    return existing

            now = get_utc_now_timestamp()

            # Record Stage 1: Quarantine Telemetry
            logger.warning(
                f"[SensorContainment] STAGE 1: Quarantining telemetry for sensor {sensor_id} "
                f"(Tenant: {tenant_id}, Trust: {trust_score}). Reason: {trigger_reason}"
            )
            record = ContainmentRecord(
                tenant_id=tenant_id,
                sensor_id=sensor_id,
                status=ContainmentStatus.QUARANTINED,
                stage=ContainmentStage.STAGE_1_QUARANTINE,
                triggered_by=triggered_by,
                trigger_reason=trigger_reason,
                trust_score=trust_score,
                quarantined_at=now,
                details=details,
            )
            self._containment_store[key] = record

            # Update DB to quarantined state
            repo = self._get_repo()
            try:
                if hasattr(repo, "collection") and hasattr(repo.collection, "update_one"):
                    await repo.collection.update_one(
                        {"sensor_id": sensor_id, "tenant_id": tenant_id},
                        {"$set": {
                            "status": "quarantined",
                            "is_active": False,
                            "quarantined_at": now,
                            "quarantine_reason": trigger_reason,
                        }}
                    )
                elif hasattr(repo, "update"):
                    await repo.update(
                        {"sensor_id": sensor_id, "tenant_id": tenant_id},
                        {
                            "status": "quarantined",
                            "is_active": False,
                            "quarantined_at": now,
                            "quarantine_reason": trigger_reason,
                        }
                    )
            except Exception as e:
                logger.error(f"[SensorContainment] DB update failed for Stage 1 quarantine on {sensor_id}: {e}")

            # Sealed Audit for Stage 1
            try:
                await self._audit.append_entry(
                    action="CONTAINMENT_QUARANTINE_TELEMETRY",
                    resource_type="sensor",
                    resource_id=sensor_id,
                    actor={"component": "AutonomousResponseController", "stage": "STAGE_1"},
                    tenant_id=tenant_id,
                    details={
                        "trust_score": trust_score,
                        "triggered_by": triggered_by,
                        "trigger_reason": trigger_reason,
                        **details,
                    },
                    status="SUCCESS",
                )
            except Exception as ae:
                logger.error(f"[SensorContainment] Audit append failed for Stage 1: {ae}")

            # Stage 2: Revoke Credentials and Disconnect Sensor
            now_stage2 = get_utc_now_timestamp()
            logger.critical(
                f"[SensorContainment] STAGE 2: Revoking credentials and disconnecting sensor {sensor_id} "
                f"(Tenant: {tenant_id})."
            )
            record.status = ContainmentStatus.REVOKED
            record.stage = ContainmentStage.STAGE_2_REVOKE
            record.revoked_at = now_stage2

            try:
                if hasattr(repo, "collection") and hasattr(repo.collection, "update_one"):
                    await repo.collection.update_one(
                        {"sensor_id": sensor_id, "tenant_id": tenant_id},
                        {"$set": {
                            "status": "revoked",
                            "is_active": False,
                            "revoked_at": now_stage2,
                            "revocation_reason": trigger_reason,
                        }}
                    )
                elif hasattr(repo, "update"):
                    await repo.update(
                        {"sensor_id": sensor_id, "tenant_id": tenant_id},
                        {
                            "status": "revoked",
                            "is_active": False,
                            "revoked_at": now_stage2,
                            "revocation_reason": trigger_reason,
                        }
                    )
            except Exception as e:
                logger.error(f"[SensorContainment] DB update failed for Stage 2 revocation on {sensor_id}: {e}")

            # Sealed Audit for Stage 2
            try:
                await self._audit.append_entry(
                    action="CONTAINMENT_REVOKE_CREDENTIALS",
                    resource_type="sensor",
                    resource_id=sensor_id,
                    actor={"component": "AutonomousResponseController", "stage": "STAGE_2"},
                    tenant_id=tenant_id,
                    details={
                        "revoked_at": now_stage2,
                        "triggered_by": triggered_by,
                        "trigger_reason": trigger_reason,
                        **details,
                    },
                    status="SUCCESS",
                )
            except Exception as ae:
                logger.error(f"[SensorContainment] Audit append failed for Stage 2: {ae}")

            return record

    def clear_containment_cache(self, sensor_id: str, tenant_id: str) -> None:
        """Removes sensor from local containment cache upon verified recovery."""
        key = (tenant_id, sensor_id)
        if key in self._containment_store:
            del self._containment_store[key]

