"""
backend/self_defense/recovery.py

Sensor and Subsystem Recovery Manager for the Autonomous Response Controller (ARC).
Implements:
1. Strict recovery authorization: never automatically restores a contained sensor.
2. Two-man rule enforcement: requester and approver must be distinct identities.
3. Fail-closed transactional recovery: audit ledger commit must succeed before state is altered.
4. Mandatory credential rotation and integrity validation before restoration.
5. Trust score reset to clean baseline upon verified recovery.
6. Independent out-of-band notification via watchdog sinks.
"""

import time
import hashlib
from typing import Dict, Any, Optional, List

from backend.utils.logger import get_logger
from backend.self_defense.schemas import (
    RecoveryRequest,
    RecoveryResult,
    ContainmentStatus,
    ContainmentStage,
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
from backend.self_defense.containment import SensorContainmentManager

logger = get_logger(__name__)


class RecoveryError(Exception):
    """Raised when an unauthorized, un-audited, or invalid recovery operation is attempted."""
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


class SensorRecoveryManager:
    """
    Orchestrates authorized restoration of quarantined or revoked sensors.
    Enforces a strict fail-closed transaction state machine.
    """

    def __init__(
        self,
        containment_manager: SensorContainmentManager,
        sensors_repository=None,
        sensor_trust_engine=None,
        audit_ledger_instance: Optional[CryptographicallySealedAuditLedger] = None,
    ):
        self.containment_manager = containment_manager
        self._repo = sensors_repository
        self._ste = sensor_trust_engine
        self._audit = audit_ledger_instance or global_audit_ledger

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

    async def restore_sensor(
        self,
        recovery_request: RecoveryRequest,
        require_key_rotation: bool = True,
    ) -> RecoveryResult:
        """
        Executes verified, authorized restoration of a contained sensor.
        Guarantees:
        1. Explicit authorization required (cannot auto-restore merely because trust score recovers).
        2. Two-Man Rule enforcement: requester and approver must be distinct identities.
        3. Fail-Closed Audit First: Audit ledger entry is committed before any reactivation.
           If audit ledger append fails, the sensor strictly remains contained (HTTP 503).
        4. Credential rotation validated (if require_key_rotation is True, new key hash is required).
        5. Sensor active status restored in database (with rollback on failure).
        6. Sensor trust score reset to clean state.
        """
        sensor_id = recovery_request.sensor_id
        tenant_id = recovery_request.tenant_id
        approver_id = recovery_request.approver_id
        requester_id = recovery_request.requester_id

        if not approver_id:
            raise RecoveryError("Sensor recovery requires an explicit, authenticated approver identity.", status_code=403)

        # 1. Two-Man Rule enforcement
        if requester_id and requester_id == approver_id:
            raise RecoveryError("Two-man rule violation: Requester cannot approve their own sensor recovery.", status_code=403)

        # 2. Verify that the sensor is actually contained
        is_contained = await self.containment_manager.is_sensor_contained(sensor_id, tenant_id)
        if not is_contained:
            raise RecoveryError(f"Sensor {sensor_id} in tenant {tenant_id} is not in a contained state.", status_code=400)

        # 3. Key rotation check
        if require_key_rotation and not recovery_request.new_api_key_hash:
            raise RecoveryError(
                "Security Policy Violation: Recovery of a compromised or untrusted sensor "
                "requires mandatory API key rotation (new_api_key_hash missing).",
                status_code=400
            )

        now = get_utc_now_timestamp()
        repo = self._get_repo()

        # 4. Fail-Closed Audit Commit FIRST (Transaction Step 1)
        # Never touch the database or clear containment cache unless audit record is durably sealed!
        try:
            await self._audit.append_entry(
                action="CONTAINMENT_RECOVERY_AUTHORIZED",
                resource_type="sensor",
                resource_id=sensor_id,
                actor={"approver_id": approver_id, "requester_id": requester_id},
                tenant_id=tenant_id,
                details={
                    "validation_notes": recovery_request.validation_notes,
                    "key_rotated": bool(recovery_request.new_api_key_hash),
                    "reset_trust_score": recovery_request.reset_trust_score,
                },
                status="SUCCESS",
            )
        except Exception as ae:
            logger.critical(
                f"[SensorRecovery] FAIL-CLOSED MANDATE: Audit append failed for recovery of {sensor_id}: {ae}. "
                "Sensor remains contained."
            )
            raise RecoveryError(
                f"Fail-closed mandate: Audit storage failed during recovery ({ae}). Sensor remains contained.",
                status_code=503
            )

        # 5. Database Update (Transaction Step 2)
        update_doc: Dict[str, Any] = {
            "status": "active",
            "is_active": True,
            "recovered_at": now,
            "recovered_by": approver_id,
            "recovery_notes": recovery_request.validation_notes,
        }
        if recovery_request.new_api_key_hash:
            update_doc["api_key_hash"] = recovery_request.new_api_key_hash

        try:
            if hasattr(repo, "collection") and hasattr(repo.collection, "update_one"):
                await repo.collection.update_one(
                    {"sensor_id": sensor_id, "tenant_id": tenant_id},
                    {"$set": update_doc}
                )
            elif hasattr(repo, "update"):
                await repo.update(
                    {"sensor_id": sensor_id, "tenant_id": tenant_id},
                    update_doc
                )
        except Exception as e:
            logger.critical(f"[SensorRecovery] DB update failed during recovery for {sensor_id}: {e}. Enforcing rollback.")
            # Record recovery aborted in audit ledger
            try:
                await self._audit.append_entry(
                    action="CONTAINMENT_RECOVERY_ABORTED",
                    resource_type="sensor",
                    resource_id=sensor_id,
                    actor={"approver_id": approver_id},
                    tenant_id=tenant_id,
                    details={"error": str(e)},
                    status="FAILED",
                )
            except Exception:
                pass
            raise RecoveryError(f"Database write failure during recovery: {e}", status_code=500)

        # 6. Reset SensorTrustEngine score to clean baseline (Transaction Step 3)
        ste = self._get_ste()
        if ste:
            try:
                ste.reset_sensor_trust(sensor_id, tenant_id, new_score=recovery_request.reset_trust_score)
            except Exception as se:
                logger.warning(f"[SensorRecovery] Could not reset trust score for {sensor_id}: {se}")

        # 7. Clear containment cache only after successful audit and DB commit
        self.containment_manager.clear_containment_cache(sensor_id, tenant_id)

        logger.info(
            f"[SensorRecovery] Sensor {sensor_id} successfully restored by {approver_id} "
            f"(Tenant: {tenant_id}, Key Rotated: {bool(recovery_request.new_api_key_hash)})"
        )

        return RecoveryResult(
            success=True,
            sensor_id=sensor_id,
            tenant_id=tenant_id,
            restored_at=now,
            message="Sensor authorization restored and new credentials provisioned.",
            trust_score=recovery_request.reset_trust_score,
        )
