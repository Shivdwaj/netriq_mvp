"""
backend/self_defense/response_controller.py

Autonomous Response Controller (ARC) for NetrIQ Stage 2 Self-Defense.
Central orchestration for automated containment, intelligence fallback,
quarantine isolation, and reversible authorized recovery.
"""

import time
import asyncio
from typing import Dict, Any, Optional, List, Tuple

from backend.utils.logger import get_logger
from backend.self_defense.schemas import (
    ContainmentStatus,
    ContainmentStage,
    ContainmentRecord,
    RecoveryRequest,
    RecoveryResult,
    SecurityAlert,
    AlertSeverity,
    AlertCategory,
    get_utc_now_timestamp,
    get_utc_now_iso,
)
from backend.self_defense.response_policies import (
    ResponsePolicyEngine,
    ResponseTriggerType,
    ResponseActionType,
    TRUST_COLLAPSE_THRESHOLD,
    DEFAULT_CONTAINMENT_MODE,
)
from backend.self_defense.containment import SensorContainmentManager
from backend.self_defense.recovery import SensorRecoveryManager, RecoveryError
from backend.self_defense.audit_ledger import (
    CryptographicallySealedAuditLedger,
    audit_ledger as global_audit_ledger,
)
from backend.self_defense.watchdog import (
    AlertSink,
    FileAlertSink,
)

logger = get_logger(__name__)


class AutonomousResponseController:
    """
    Autonomous Response Controller (ARC).
    Orchestrates:
    1. Staged autonomous sensor containment upon trust collapse (Option B).
    2. Idempotent action execution avoiding duplicate destruction.
    3. Multi-tenant pipeline isolation.
    4. Intelligence fallback to Safe Detection Mode (disables untrusted ML and suspends automated blocks).
    5. Authorized, reversible recovery with mandatory key rotation.
    6. Sealed audit trails and independent out-of-band alerts.
    """

    def __init__(
        self,
        audit_ledger_instance: Optional[CryptographicallySealedAuditLedger] = None,
        alert_sinks: Optional[List[AlertSink]] = None,
        sensors_repository=None,
        sensor_trust_engine=None,
    ):
        self.audit_ledger = audit_ledger_instance or global_audit_ledger
        self.alert_sinks: List[AlertSink] = alert_sinks or []
        if not self.alert_sinks:
            self.alert_sinks.append(FileAlertSink())

        self.policy_engine = ResponsePolicyEngine()
        self.containment_manager = SensorContainmentManager(
            sensors_repository=sensors_repository,
            sensor_trust_engine=sensor_trust_engine,
            audit_ledger_instance=self.audit_ledger,
        )
        self.recovery_manager = SensorRecoveryManager(
            containment_manager=self.containment_manager,
            sensors_repository=sensors_repository,
            sensor_trust_engine=sensor_trust_engine,
            audit_ledger_instance=self.audit_ledger,
        )

        self._automated_blocks_suspended = False
        self._lock = asyncio.Lock()

    def add_alert_sink(self, sink: AlertSink) -> None:
        """Registers an independent out-of-band alert sink."""
        self.alert_sinks.append(sink)

    async def broadcast_alert(self, alert: SecurityAlert) -> None:
        """Emits alert across all registered out-of-band alert sinks."""
        for sink in self.alert_sinks:
            try:
                await sink.emit_alert(alert)
            except Exception as e:
                logger.error(f"[ARC] Error emitting alert: {e}")

    # ==========================================================================
    # 1. Sensor Containment (Option B: Staged Autonomous Containment)
    # ==========================================================================

    async def handle_trust_collapse(
        self,
        sensor_id: str,
        tenant_id: str,
        trust_score: float,
        reason: str = "Sensor trust score collapsed below 0.50 threshold",
        details: Optional[Dict[str, Any]] = None,
    ) -> ContainmentRecord:
        """
        Coordinates staged autonomous containment for a sensor whose trust has collapsed.
        Option B (Staged Autonomous Containment):
        Stage 1: Immediately quarantine incoming telemetry batches and block new authentication.
        Stage 2: Revoke API key credentials, disconnect sensor, and mark sensor revoked.
        
        Guarantees:
        - Strict tenant isolation (affects only tenant_id, sensor_id).
        - Idempotency: repeated triggers do not re-execute or corrupt state.
        - Sealed audit trail.
        - Out-of-band alert dispatch.
        """
        details = details or {}

        # 1. Check if trust score is truly below collapse threshold
        if trust_score >= TRUST_COLLAPSE_THRESHOLD:
            logger.info(
                f"[ARC] Sensor {sensor_id} trust score ({trust_score}) is not below collapse threshold "
                f"({TRUST_COLLAPSE_THRESHOLD}). No containment action taken."
            )
            rec = await self.containment_manager.get_containment_record(sensor_id, tenant_id)
            if rec:
                return rec
            return ContainmentRecord(
                tenant_id=tenant_id,
                sensor_id=sensor_id,
                status=ContainmentStatus.ACTIVE,
                stage=ContainmentStage.STAGE_1_QUARANTINE,
                trust_score=trust_score,
            )

        # 2. Check if already contained (Idempotency)
        already_contained = await self.containment_manager.is_sensor_contained(sensor_id, tenant_id)
        if already_contained:
            existing_record = await self.containment_manager.get_containment_record(sensor_id, tenant_id)
            if existing_record:
                logger.info(
                    f"[ARC] Sensor {sensor_id} in tenant {tenant_id} is already contained "
                    f"(Status: {existing_record.status.value}). Idempotent bypass."
                )
                return existing_record

        # 3. Execute Staged Containment
        record = await self.containment_manager.execute_staged_containment(
            sensor_id=sensor_id,
            tenant_id=tenant_id,
            trust_score=trust_score,
            triggered_by="STE_TRUST_COLLAPSE",
            trigger_reason=reason,
            details=details,
        )

        # 4. Out-of-band critical alert
        alert = SecurityAlert(
            severity=AlertSeverity.CRITICAL,
            category=AlertCategory.CONTAINMENT_TRIGGERED,
            source="autonomous_response_controller.sensor_containment",
            message=(
                f"Sensor '{sensor_id}' contained autonomously under tenant '{tenant_id}'. "
                f"Trust score: {trust_score:.2f} (< {TRUST_COLLAPSE_THRESHOLD:.2f}). "
                f"Telemetry quarantined and credentials revoked."
            ),
            details={
                "sensor_id": sensor_id,
                "tenant_id": tenant_id,
                "trust_score": trust_score,
                "containment_status": record.status.value,
                "stage": record.stage.value,
                "reason": reason,
                **details,
            },
        )
        await self.broadcast_alert(alert)

        return record

    async def quarantine_sensor(
        self,
        sensor_id: str,
        tenant_id: str,
        trust_score: Optional[float] = None,
        reason: str = "Sensor telemetry quarantined",
        details: Optional[Dict[str, Any]] = None,
    ) -> ContainmentRecord:
        """Executes Stage 1: Immediate telemetry quarantine and session eviction."""
        record = await self.containment_manager.quarantine_sensor(
            sensor_id=sensor_id,
            tenant_id=tenant_id,
            trust_score=trust_score,
            trigger_reason=reason,
            details=details,
        )
        alert = SecurityAlert(
            severity=AlertSeverity.HIGH,
            category=AlertCategory.CONTAINMENT_TRIGGERED,
            source="arc.sensor_quarantine",
            message=f"Sensor '{sensor_id}' quarantined in tenant '{tenant_id}'. Telemetry isolated.",
            details={"sensor_id": sensor_id, "tenant_id": tenant_id, "stage": "STAGE_1"},
        )
        await self.broadcast_alert(alert)
        return record

    async def confirm_and_escalate_revocation(
        self,
        sensor_id: str,
        tenant_id: str,
        confirmation_reason: str = "Confirmation gate passed: persistent trust collapse",
        details: Optional[Dict[str, Any]] = None,
        bypass_trust_recheck: bool = False,
    ) -> ContainmentRecord:
        """Executes Stage 2: Verified credential revocation guarded by confirmation gate."""
        record = await self.containment_manager.confirm_and_escalate_revocation(
            sensor_id=sensor_id,
            tenant_id=tenant_id,
            confirmation_reason=confirmation_reason,
            details=details,
            bypass_trust_recheck=bypass_trust_recheck,
        )
        if record.status == ContainmentStatus.REVOKED:
            alert = SecurityAlert(
                severity=AlertSeverity.CRITICAL,
                category=AlertCategory.CONTAINMENT_TRIGGERED,
                source="arc.sensor_revocation",
                message=f"Sensor '{sensor_id}' credentials revoked in tenant '{tenant_id}' after confirmation.",
                details={"sensor_id": sensor_id, "tenant_id": tenant_id, "stage": "STAGE_2"},
            )
            await self.broadcast_alert(alert)
        return record

    async def is_sensor_contained(self, sensor_id: str, tenant_id: str) -> bool:
        """Returns True if the sensor is quarantined or revoked."""
        return await self.containment_manager.is_sensor_contained(sensor_id, tenant_id)

    async def is_sensor_quarantined(self, sensor_id: str, tenant_id: str) -> bool:
        """Returns True if the sensor is quarantined or revoked."""
        return await self.is_sensor_contained(sensor_id, tenant_id)

    # ==========================================================================
    # 2. Intelligence Fallback (Safe Mode Activation & Automated Blocks Suspension)
    # ==========================================================================

    async def handle_intelligence_tampering(
        self,
        iig_verdict: Any,
        source: str = "watchdog",
    ) -> Dict[str, Any]:
        """
        Activates Safe Detection Mode when model, rule, or configuration tampering is detected:
        1. Activates Safe Mode in IntelligenceIntegrityGuard (disabling ML inference).
        2. Suspends unverified automated firewall blocks to prevent weaponization of compromised AI.
        3. Preserves deterministic detection (Suricata signatures and rule engines continue running).
        4. Dispatches out-of-band CRITICAL alert.
        5. Records sealed audit entry.
        """
        async with self._lock:
            now = get_utc_now_timestamp()
            failed_assets = getattr(iig_verdict, "failed_assets", [])
            error_message = getattr(iig_verdict, "error_message", str(iig_verdict))

            from backend.self_defense.intelligence_guard import intelligence_guard
            intelligence_guard.activate_safe_mode(reason=error_message)
            self._automated_blocks_suspended = True

            logger.critical(
                f"[ARC] INTELLIGENCE TAMPERING RESPONSE: Safe Mode ACTIVATED. "
                f"Automated blocks SUSPENDED. Deterministic detection preserved. Source: {source}. Details: {error_message}"
            )

            # Sealed Audit
            try:
                await self.audit_ledger.append_entry(
                    action="SAFE_MODE_ACTIVATED",
                    resource_type="intelligence",
                    resource_id="ml_models",
                    actor={"component": "AutonomousResponseController", "source": source},
                    details={
                        "failed_assets": failed_assets,
                        "error_message": error_message,
                        "automated_blocks_suspended": True,
                    },
                    status="SUCCESS",
                )
            except Exception as ae:
                logger.error(f"[ARC] Audit append failed for Safe Mode activation: {ae}")

            # Out-of-band alert
            alert = SecurityAlert(
                severity=AlertSeverity.CRITICAL,
                category=AlertCategory.SAFE_MODE_ACTIVATED,
                source=f"arc.{source}",
                message=f"Safe Detection Mode activated due to intelligence tampering: {error_message}",
                details={
                    "failed_assets": failed_assets,
                    "automated_blocks_suspended": True,
                    "safe_mode_active": True,
                },
            )
            await self.broadcast_alert(alert)

            return {
                "safe_mode_active": True,
                "automated_blocks_suspended": True,
                "timestamp": now,
                "message": "Safe Detection Mode activated; untrusted ML disabled; automated blocks suspended.",
            }

    async def handle_intelligence_recovery(
        self,
        approver_id: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Deactivates Safe Mode and restores normal automated responses once models are validated.
        Requires explicit administrator approval.
        """
        async with self._lock:
            from backend.self_defense.intelligence_guard import intelligence_guard
            intelligence_guard.deactivate_safe_mode()
            self._automated_blocks_suspended = False

            now = get_utc_now_timestamp()
            logger.info(f"[ARC] Safe Mode DEACTIVATED by {approver_id}. Automated blocks resumed.")

            # Sealed Audit
            try:
                await self.audit_ledger.append_entry(
                    action="SAFE_MODE_DEACTIVATED",
                    resource_type="intelligence",
                    resource_id="ml_models",
                    actor={"approver_id": approver_id},
                    details={"notes": notes, "automated_blocks_resumed": True},
                    status="SUCCESS",
                )
            except Exception as ae:
                logger.error(f"[ARC] Audit append failed for Safe Mode deactivation: {ae}")

            # Out-of-band alert
            alert = SecurityAlert(
                severity=AlertSeverity.INFO,
                category=AlertCategory.SAFE_MODE_DEACTIVATED,
                source="arc.recovery",
                message=f"Safe Detection Mode deactivated by {approver_id}. Normal ML operations restored.",
                details={"approver_id": approver_id, "notes": notes},
            )
            await self.broadcast_alert(alert)

            return {
                "safe_mode_active": False,
                "automated_blocks_suspended": False,
                "timestamp": now,
                "message": "Safe Mode deactivated; normal ML operations and automated blocks resumed.",
            }

    def are_automated_blocks_suspended(self) -> bool:
        """Returns True if unverified automated firewall/quarantine mitigations are currently suspended."""
        from backend.self_defense.intelligence_guard import intelligence_guard
        return self._automated_blocks_suspended or intelligence_guard.is_safe_mode_active()

    def is_safe_mode_active(self) -> bool:
        """Returns True if Safe Detection Mode is currently active."""
        from backend.self_defense.intelligence_guard import intelligence_guard
        return intelligence_guard.is_safe_mode_active()

    # ==========================================================================
    # 3. Authorized Sensor Recovery
    # ==========================================================================

    async def authorize_sensor_recovery(
        self,
        recovery_request: RecoveryRequest,
        require_key_rotation: bool = True,
    ) -> RecoveryResult:
        """
        Authorizes the restoration of a quarantined/revoked sensor.
        Delegates to SensorRecoveryManager.
        """
        result = await self.recovery_manager.restore_sensor(
            recovery_request=recovery_request,
            require_key_rotation=require_key_rotation,
        )

        # Broadcast out-of-band alert
        alert = SecurityAlert(
            severity=AlertSeverity.INFO,
            category=AlertCategory.CONTAINMENT_RECOVERY,
            source="arc.recovery_manager",
            message=f"Sensor '{recovery_request.sensor_id}' restored in tenant '{recovery_request.tenant_id}' by '{recovery_request.approver_id}'.",
            details={
                "sensor_id": recovery_request.sensor_id,
                "tenant_id": recovery_request.tenant_id,
                "approver_id": recovery_request.approver_id,
                "key_rotated": bool(recovery_request.new_api_key_hash),
            },
        )
        await self.broadcast_alert(alert)

        return result


# Global Singleton Instance
response_controller = AutonomousResponseController()
