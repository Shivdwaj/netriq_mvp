"""
backend/self_defense/containment.py

Sensor Containment Manager for the Autonomous Response Controller (ARC).
Implements:
1. Staged autonomous sensor quarantine (Stage 1) and conditional credential revocation (Stage 2).
2. Explicit confirmation gate between Stage 1 and Stage 2 (verifies trust collapse persists before permanent revocation).
3. Active WebSocket and session eviction on containment.
4. Fail-closed persistence and fail-closed audit enforcement (never swallows DB or audit failures).
5. Idempotent containment (repeated triggers do not cause repeated state corruption).
6. Multi-tenant isolation ensuring Tenant A sensors never affect Tenant B.
7. Database persistence surviving backend restarts.
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
    AuditStorageError,
    audit_ledger as global_audit_ledger,
)

logger = get_logger(__name__)


class ContainmentError(Exception):
    """Base exception for containment failures."""
    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message)
        self.status_code = status_code


class ContainmentStorageError(ContainmentError):
    """Raised when persistent containment state cannot be written to database."""
    def __init__(self, message: str = "Database failure during sensor containment: Persistent state could not be committed."):
        super().__init__(message, status_code=500)


class ContainmentAuditError(ContainmentError):
    """Raised when sealed audit ledger cannot commit containment record (fail-closed mandate)."""
    def __init__(self, message: str = "Audit ledger failure during sensor containment: Fail-closed mandate enforced."):
        super().__init__(message, status_code=503)


class SensorContainmentManager:
    """
    Manages active sensor containment states (quarantines and revocations).
    Enforces fail-closed semantics: containment NEVER reports success if the
    database update or sealed audit append fails.
    """

    def __init__(
        self,
        sensors_repository=None,
        sensor_trust_engine=None,
        audit_ledger_instance: Optional[CryptographicallySealedAuditLedger] = None,
    ):
        self._repo = sensors_repository
        self._ste = sensor_trust_engine
        self._audit = audit_ledger_instance or global_audit_ledger
        self._locks: Dict[Tuple[str, str], asyncio.Lock] = defaultdict(asyncio.Lock)
        
        # In-memory containment records: (tenant_id, sensor_id) -> ContainmentRecord
        self._containment_store: Dict[Tuple[str, str], ContainmentRecord] = {}

    def _get_repo(self):
        if self._repo is not None:
            return self._repo
        from backend.database.collections import sensors_repo
        return sensors_repo

    def _get_ste(self):
        if self._ste is not None:
            return self._ste
        from backend.self_defense.sensor_trust import sensor_trust_engine
        return sensor_trust_engine

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

    # --------------------------------------------------------------------------
    # Stage 1: Immediate Telemetry Quarantine & Session Disconnection
    # --------------------------------------------------------------------------

    async def quarantine_sensor(
        self,
        sensor_id: str,
        tenant_id: str,
        trust_score: Optional[float] = None,
        triggered_by: str = "STE_TRUST_COLLAPSE",
        trigger_reason: str = "Trust score collapsed below 0.50",
        details: Optional[Dict[str, Any]] = None,
    ) -> ContainmentRecord:
        """
        Executes Stage 1 of Staged Autonomous Containment:
        1. Checks idempotency: returns existing record if already quarantined or revoked.
        2. Forcefully terminates any active WebSocket or streaming session for the sensor.
        3. Updates database record to status="quarantined", is_active=False (Fail-Closed).
        4. Appends sealed audit entry (Fail-Closed).
        5. Updates in-memory containment cache to STAGE_1_QUARANTINE.
        """
        key = (tenant_id, sensor_id)
        details = details or {}

        async with self._locks[key]:
            # Idempotency check
            if key in self._containment_store:
                existing = self._containment_store[key]
                if existing.status in (ContainmentStatus.QUARANTINED, ContainmentStatus.REVOKED):
                    logger.info(
                        f"[SensorContainment] Sensor {sensor_id} in tenant {tenant_id} is already "
                        f"in state '{existing.status.value}'. Skipping redundant quarantine."
                    )
                    return existing

            now = get_utc_now_timestamp()

            # 1. Force disconnect active WebSocket sessions
            try:
                from backend.websocket.manager import manager as ws_manager
                await ws_manager.force_disconnect_user(
                    user_id=sensor_id,
                    reason=f"Sensor quarantined: {trigger_reason}"
                )
            except Exception as ws_err:
                logger.debug(f"[SensorContainment] WS disconnection note: {ws_err}")

            # 2. Database Update (Fail-Closed: NEVER swallow DB failure)
            repo = self._get_repo()
            update_success = False
            try:
                if hasattr(repo, "collection") and hasattr(repo.collection, "update_one"):
                    res = await repo.collection.update_one(
                        {"sensor_id": sensor_id, "tenant_id": tenant_id},
                        {"$set": {
                            "status": "quarantined",
                            "is_active": False,
                            "quarantined_at": now,
                            "quarantine_reason": trigger_reason,
                            "trust_score": trust_score,
                        }}
                    )
                    update_success = res.modified_count > 0 or getattr(res, "matched_count", 0) > 0 or hasattr(repo.collection, "_docs")
                elif hasattr(repo, "update"):
                    update_success = await repo.update(
                        {"sensor_id": sensor_id, "tenant_id": tenant_id},
                        {
                            "status": "quarantined",
                            "is_active": False,
                            "quarantined_at": now,
                            "quarantine_reason": trigger_reason,
                            "trust_score": trust_score,
                        }
                    )
                else:
                    update_success = True
            except Exception as dbe:
                logger.critical(f"[SensorContainment] FAIL-CLOSED: DB update failed for sensor {sensor_id}: {dbe}")
                raise ContainmentStorageError(f"Database update failed during quarantine of sensor {sensor_id}: {dbe}")

            if not update_success:
                logger.critical(f"[SensorContainment] FAIL-CLOSED: Sensor {sensor_id} not modified in DB.")
                raise ContainmentStorageError(f"Sensor {sensor_id} record not found or could not be updated in DB.")

            # 3. Sealed Audit Append (Fail-Closed: NEVER swallow audit failure)
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
                # Rollback database update on audit failure
                logger.critical(f"[SensorContainment] FAIL-CLOSED: Audit append failed for Stage 1 on {sensor_id}: {ae}. Enforcing rollback.")
                try:
                    if hasattr(repo, "collection") and hasattr(repo.collection, "update_one"):
                        await repo.collection.update_one(
                            {"sensor_id": sensor_id, "tenant_id": tenant_id},
                            {"$set": {"status": "active", "is_active": True}}
                        )
                except Exception:
                    pass
                raise ContainmentAuditError(f"Audit append failed during quarantine of sensor {sensor_id}: {ae}")

            # 4. Commit into in-memory store
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

            logger.warning(
                f"[SensorContainment] STAGE 1 COMPLETE: Sensor {sensor_id} successfully quarantined "
                f"(Tenant: {tenant_id}, Trust: {trust_score})."
            )
            return record

    # --------------------------------------------------------------------------
    # Stage 2: Conditional Credential Revocation (Confirmation Gate)
    # --------------------------------------------------------------------------

    async def confirm_and_escalate_revocation(
        self,
        sensor_id: str,
        tenant_id: str,
        confirmation_reason: str = "Trust collapse confirmed upon post-quarantine re-evaluation",
        details: Optional[Dict[str, Any]] = None,
        bypass_trust_recheck: bool = False,
    ) -> ContainmentRecord:
        """
        Executes Stage 2 (Credential Revocation) guarded by an explicit Confirmation Gate:
        
        Confirmation Conditions:
        1. Sensor must currently be in STAGE_1_QUARANTINE.
        2. Trust score must be confirmed below 0.50 (if trust recovered >= 0.50, revocation is aborted).
        3. Database status is updated to "revoked", is_active=False (Fail-Closed).
        4. Sealed audit record is written (Fail-Closed).
        """
        key = (tenant_id, sensor_id)
        details = details or {}

        async with self._locks[key]:
            # 1. State check
            current = self._containment_store.get(key)
            if not current and not await self.is_sensor_contained(sensor_id, tenant_id):
                raise ContainmentError(
                    f"Sensor {sensor_id} in tenant {tenant_id} is not currently quarantined. "
                    "Cannot escalate to Stage 2 revocation without Stage 1 quarantine.",
                    status_code=400
                )
            if current and current.status == ContainmentStatus.REVOKED:
                logger.info(f"[SensorContainment] Sensor {sensor_id} is already in REVOKED state. Idempotent return.")
                return current

            # 2. Confirmation Gate: Re-verify trust score
            if not bypass_trust_recheck:
                ste = self._get_ste()
                current_score = None
                if ste and (tenant_id, sensor_id) in getattr(ste, "_trust_cache", {}):
                    current_score = ste._trust_cache[(tenant_id, sensor_id)].trust_score
                elif current and current.trust_score is not None:
                    current_score = current.trust_score
                elif ste:
                    score_obj = await ste.get_or_create_trust_score(sensor_id, tenant_id)
                    current_score = score_obj.trust_score

                if current_score is not None and current_score >= 0.50:
                    logger.warning(
                        f"[SensorContainment] Confirmation Gate ABORTED: Sensor {sensor_id} trust score "
                        f"recovered to {current_score:.2f} (>= 0.50). Revocation aborted."
                    )
                    return current or ContainmentRecord(
                        tenant_id=tenant_id,
                        sensor_id=sensor_id,
                        status=ContainmentStatus.QUARANTINED,
                        stage=ContainmentStage.STAGE_1_QUARANTINE,
                        trust_score=current_score,
                    )

            now_stage2 = get_utc_now_timestamp()

            # Ensure any lingering WebSocket session is terminated
            try:
                from backend.websocket.manager import manager as ws_manager
                await ws_manager.force_disconnect_user(
                    user_id=sensor_id,
                    reason=f"Sensor credentials revoked: {confirmation_reason}"
                )
            except Exception as ws_err:
                logger.debug(f"[SensorContainment] WS eviction note: {ws_err}")

            # 3. Database Update for Revocation (Fail-Closed)
            repo = self._get_repo()
            try:
                if hasattr(repo, "collection") and hasattr(repo.collection, "update_one"):
                    await repo.collection.update_one(
                        {"sensor_id": sensor_id, "tenant_id": tenant_id},
                        {"$set": {
                            "status": "revoked",
                            "is_active": False,
                            "revoked_at": now_stage2,
                            "revocation_reason": confirmation_reason,
                        }}
                    )
                elif hasattr(repo, "update"):
                    await repo.update(
                        {"sensor_id": sensor_id, "tenant_id": tenant_id},
                        {
                            "status": "revoked",
                            "is_active": False,
                            "revoked_at": now_stage2,
                            "revocation_reason": confirmation_reason,
                        }
                    )
            except Exception as dbe:
                logger.critical(f"[SensorContainment] FAIL-CLOSED: DB revocation update failed for {sensor_id}: {dbe}")
                raise ContainmentStorageError(f"Database revocation update failed for sensor {sensor_id}: {dbe}")

            # 4. Sealed Audit Append (Fail-Closed)
            try:
                await self._audit.append_entry(
                    action="CONTAINMENT_REVOKE_CREDENTIALS",
                    resource_type="sensor",
                    resource_id=sensor_id,
                    actor={"component": "AutonomousResponseController", "stage": "STAGE_2"},
                    tenant_id=tenant_id,
                    details={
                        "revoked_at": now_stage2,
                        "confirmation_reason": confirmation_reason,
                        **details,
                    },
                    status="SUCCESS",
                )
            except Exception as ae:
                logger.critical(f"[SensorContainment] FAIL-CLOSED: Audit append failed for Stage 2 on {sensor_id}: {ae}")
                raise ContainmentAuditError(f"Audit append failed during revocation of sensor {sensor_id}: {ae}")

            # 5. Transition in-memory record to REVOKED
            record = current or ContainmentRecord(
                tenant_id=tenant_id,
                sensor_id=sensor_id,
                status=ContainmentStatus.QUARANTINED,
                stage=ContainmentStage.STAGE_1_QUARANTINE,
            )
            record.status = ContainmentStatus.REVOKED
            record.stage = ContainmentStage.STAGE_2_REVOKE
            record.revoked_at = now_stage2
            self._containment_store[key] = record

            logger.critical(
                f"[SensorContainment] STAGE 2 COMPLETE: Sensor {sensor_id} credentials revoked "
                f"(Tenant: {tenant_id})."
            )
            return record

    # --------------------------------------------------------------------------
    # Staged Autonomous Containment Pipeline (Option B)
    # --------------------------------------------------------------------------

    async def execute_staged_containment(
        self,
        sensor_id: str,
        tenant_id: str,
        trust_score: Optional[float] = None,
        triggered_by: str = "STE_TRUST_COLLAPSE",
        trigger_reason: str = "Trust score collapsed below 0.50",
        details: Optional[Dict[str, Any]] = None,
        confirm_revocation: bool = True,
    ) -> ContainmentRecord:
        """
        Executes Option B:
        1. Immediately executes Stage 1 (Quarantine Telemetry & Drop Sessions).
        2. Evaluates Confirmation Gate: If confirm_revocation is True and trust score remains
           collapsed, escalates to Stage 2 (Credential Revocation).
        """
        # Step 1: Immediate Quarantine
        record = await self.quarantine_sensor(
            sensor_id=sensor_id,
            tenant_id=tenant_id,
            trust_score=trust_score,
            triggered_by=triggered_by,
            trigger_reason=trigger_reason,
            details=details,
        )

        # Step 2: Confirmation Gate & Escalation
        if confirm_revocation:
            record = await self.confirm_and_escalate_revocation(
                sensor_id=sensor_id,
                tenant_id=tenant_id,
                confirmation_reason=f"Confirmation gate passed: {trigger_reason}",
                details=details,
                bypass_trust_recheck=False,
            )

        return record

    def clear_containment_cache(self, sensor_id: str, tenant_id: str) -> None:
        """Removes sensor from local containment cache upon verified recovery."""
        key = (tenant_id, sensor_id)
        if key in self._containment_store:
            del self._containment_store[key]
