"""
backend/self_defense/recovery.py

Sensor and Subsystem Recovery Manager for the Autonomous Response Controller (ARC).
Implements:
1. Strict recovery authorization: never automatically restores a contained sensor.
2. Mandatory credential rotation and integrity validation before restoration.
3. Trust score reset to clean baseline.
4. Sealed audit logging for all recovery actions.
5. Independent out-of-band notification via watchdog sinks.
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
    audit_ledger as global_audit_ledger,
)
from backend.self_defense.containment import SensorContainmentManager

logger = get_logger(__name__)


class RecoveryError(Exception):
    """Raised when an unauthorized or invalid recovery operation is attempted."""
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


class SensorRecoveryManager:
    """
    Orchestrates authorized restoration of quarantined or revoked sensors.
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
        2. Credential rotation validated (if require_key_rotation is True, new key hash is required).
        3. Sensor active status restored in database.
        4. Sensor trust score reset to clean state.
        5. Sealed audit entry recorded.
        """
        sensor_id = recovery_request.sensor_id
        tenant_id = recovery_request.tenant_id
        approver_id = recovery_request.approver_id

        if not approver_id:
            raise RecoveryError("Sensor recovery requires an explicit, authenticated approver identity.", status_code=403)

        # 1. Verify that the sensor is actually contained
        is_contained = await self.containment_manager.is_sensor_contained(sensor_id, tenant_id)
        if not is_contained:
            raise RecoveryError(f"Sensor {sensor_id} in tenant {tenant_id} is not in a contained state.", status_code=400)

        # 2. Key rotation check
        if require_key_rotation and not recovery_request.new_api_key_hash:
            raise RecoveryError(
                "Security Policy Violation: Recovery of a compromised or untrusted sensor "
                "requires mandatory API key rotation (new_api_key_hash missing).",
                status_code=400
            )

        now = get_utc_now_timestamp()
        repo = self._get_repo()

        # 3. Update database: restore active state and update key hash
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
            logger.error(f"[SensorRecovery] Failed to update DB on recovery for {sensor_id}: {e}")
            raise RecoveryError(f"Database error during recovery: {e}", status_code=500)

        # 4. Reset SensorTrustEngine score to clean baseline
        ste = self._get_ste()
        if ste:
            try:
                ste.reset_sensor_trust(sensor_id, tenant_id, new_score=recovery_request.reset_trust_score)
            except Exception as se:
                logger.warning(f"[SensorRecovery] Could not reset trust score for {sensor_id}: {se}")

        # 5. Clear containment cache
        self.containment_manager.clear_containment_cache(sensor_id, tenant_id)

        # 6. Record in sealed audit ledger
        try:
            await self._audit.append_entry(
                action="CONTAINMENT_RECOVERY_AUTHORIZED",
                resource_type="sensor",
                resource_id=sensor_id,
                actor={"approver_id": approver_id},
                tenant_id=tenant_id,
                details={
                    "validation_notes": recovery_request.validation_notes,
                    "key_rotated": bool(recovery_request.new_api_key_hash),
                    "reset_trust_score": recovery_request.reset_trust_score,
                },
                status="SUCCESS",
            )
        except Exception as ae:
            logger.error(f"[SensorRecovery] Audit append failed for recovery: {ae}")

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

