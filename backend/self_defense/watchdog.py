"""
backend/self_defense/watchdog.py

Independent Security Watchdog for Stage 2 Self-Defense.
Operates across an independent fault domain to continuously verify
audit ledger integrity, detect storage failures, and dispatch critical
alerts through dedicated out-of-band channels.
"""

import os
import sys
import json
import time
import signal
import asyncio
import argparse
from pathlib import Path
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any, Union

from backend.utils.logger import get_logger
from backend.self_defense.schemas import (
    SecurityAlert,
    AlertSeverity,
    AlertCategory,
    AuditVerificationResult,
    TamperType,
    get_utc_now_timestamp,
    get_utc_now_iso,
)
from backend.self_defense.audit_ledger import (
    CryptographicallySealedAuditLedger,
    AuditStorageError,
    audit_ledger as global_audit_ledger,
)

logger = get_logger(__name__)

DEFAULT_ALERT_FILE = os.getenv("NETRIQ_SECURITY_ALERT_FILE", "storage/alerts/security_alerts.jsonl")
DEFAULT_SWEEP_INTERVAL = float(os.getenv("NETRIQ_WATCHDOG_INTERVAL_SECONDS", "30.0"))


# ==============================================================================
# Out-of-Band Alert Sinks
# ==============================================================================

class AlertSink(ABC):
    """Abstract interface for independent out-of-band alert sinks."""

    @abstractmethod
    async def emit_alert(self, alert: SecurityAlert) -> None:
        """Dispatches a security alert independently of the primary event bus."""
        pass


class FileAlertSink(AlertSink):
    """
    Appends high-priority alerts to an isolated, append-only security log file.
    Operates outside the application event bus and database connection pool.
    """
    def __init__(self, file_path: Union[str, Path] = DEFAULT_ALERT_FILE):
        self.file_path = Path(file_path)
        self._ensure_dir()

    def _ensure_dir(self):
        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning(f"[FileAlertSink] Could not create alert directory: {e}")

    async def emit_alert(self, alert: SecurityAlert) -> None:
        try:
            self._ensure_dir()
            line = alert.model_dump_json() + "\n"
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            logger.critical(
                f"[FileAlertSink] OUT-OF-BAND ALERT DISPATCHED: [{alert.severity.value}] "
                f"[{alert.category.value}] {alert.message}"
            )
        except Exception as e:
            # Fallback to sys.stderr so alerts are never silently dropped
            sys.stderr.write(f"FATAL: FileAlertSink failed to write alert: {e}\n{alert.model_dump_json()}\n")
            sys.stderr.flush()

    def read_alerts(self) -> List[SecurityAlert]:
        """Reads all persisted alerts for auditing and test assertions."""
        if not self.file_path.exists():
            return []
        alerts: List[SecurityAlert] = []
        with open(self.file_path, "r", encoding="utf-8") as f:
            for line in f:
                line_clean = line.strip()
                if line_clean:
                    try:
                        alerts.append(SecurityAlert(**json.loads(line_clean)))
                    except Exception:
                        pass
        return alerts

    def clear(self) -> None:
        """Clears the alert file (used in tests)."""
        if self.file_path.exists():
            try:
                self.file_path.unlink()
            except Exception:
                pass


class MemoryAlertSink(AlertSink):
    """
    In-memory alert sink for programmatic verification and fast test validation.
    """
    def __init__(self):
        self.alerts: List[SecurityAlert] = []

    async def emit_alert(self, alert: SecurityAlert) -> None:
        self.alerts.append(alert)
        logger.warning(f"[MemoryAlertSink] Alert captured: {alert.category.value} - {alert.message}")

    def clear(self):
        self.alerts.clear()


# ==============================================================================
# Independent Security Watchdog Service
# ==============================================================================

class IndependentSecurityWatchdog:
    """
    Independent Security Watchdog process/service.
    Maintains fault-domain separation from the primary detection pipeline.
    Periodically validates audit chain integrity and storage availability,
    broadcasting critical alerts via out-of-band sinks.
    """

    def __init__(
        self,
        ledger: Optional[CryptographicallySealedAuditLedger] = None,
        alert_sinks: Optional[List[AlertSink]] = None,
        interval_seconds: float = DEFAULT_SWEEP_INTERVAL,
    ):
        self.ledger = ledger or global_audit_ledger
        self.alert_sinks: List[AlertSink] = alert_sinks if alert_sinks is not None else [FileAlertSink()]
        self.interval_seconds = interval_seconds
        self._running = False
        self._stop_event = asyncio.Event()

        # Telemetry state
        self.last_check_timestamp: Optional[float] = None
        self.last_result: Optional[AuditVerificationResult] = None
        self.sweep_count = 0
        self.tamper_alert_count = 0

    def add_alert_sink(self, sink: AlertSink) -> None:
        """Registers an additional out-of-band alert sink."""
        self.alert_sinks.append(sink)

    async def broadcast_alert(self, alert: SecurityAlert) -> None:
        """Dispatches an alert to all registered independent sinks."""
        for sink in self.alert_sinks:
            try:
                await sink.emit_alert(alert)
            except Exception as e:
                logger.error(f"[Watchdog] Error in alert sink {sink}: {e}")

    async def run_sweep(self) -> AuditVerificationResult:
        """
        Executes a single end-to-end integrity and health sweep:
        1. Checks audit storage accessibility.
        2. Validates mathematical hash chain, signatures, and external anchors.
        3. Dispatches out-of-band critical alerts on any deviation.
        """
        self.sweep_count += 1
        now = get_utc_now_timestamp()
        self.last_check_timestamp = now

        # Step 1: Storage Availability Check
        try:
            await self.ledger.check_storage_health()
        except AuditStorageError as se:
            logger.critical(f"[Watchdog] Audit storage health check failed: {se}")
            storage_alert = SecurityAlert(
                severity=AlertSeverity.CRITICAL,
                category=AlertCategory.STORAGE_FAILURE,
                source="watchdog.storage_guard",
                message=f"Audit storage failure: {se}",
                details={"error": str(se), "timestamp": now},
            )
            await self.broadcast_alert(storage_alert)
            self.last_result = AuditVerificationResult(
                is_valid=False,
                error_message=f"Audit storage failure: {se}",
                tamper_type=TamperType.NONE,
            )
            return self.last_result

        # Step 2: Mathematical Verification Check
        try:
            result = await self.ledger.verify_integrity()
            self.last_result = result

            if not result.is_valid:
                self.tamper_alert_count += 1
                logger.critical(
                    f"[Watchdog] AUDIT TAMPER DETECTED: Type={result.tamper_type.value}, "
                    f"Seq={result.tampered_sequence}, Detail={result.error_message}"
                )
                tamper_alert = SecurityAlert(
                    severity=AlertSeverity.CRITICAL,
                    category=AlertCategory.AUDIT_TAMPERING,
                    source="watchdog.chain_verifier",
                    message=(
                        f"Cryptographic audit tamper detected [{result.tamper_type.value}]: "
                        f"{result.error_message}"
                    ),
                    details={
                        "tamper_type": result.tamper_type.value,
                        "tampered_sequence": result.tampered_sequence,
                        "tampered_entry_id": result.tampered_entry_id,
                        "total_records": result.total_records,
                        "verified_anchors": result.verified_anchors,
                    },
                )
                await self.broadcast_alert(tamper_alert)
            else:
                logger.debug(
                    f"[Watchdog] Audit verification passed cleanly: "
                    f"{result.total_records} records, {result.verified_anchors} anchors."
                )

            # Step 3: Intelligence Integrity Check (Stage 2 Step 4)
            try:
                from backend.self_defense.intelligence_guard import intelligence_guard
                iig_verdict = await intelligence_guard.run_integrity_sweep()
                self.last_intelligence_result = iig_verdict
                if not iig_verdict.is_valid:
                    self.tamper_alert_count += 1
                    logger.critical(
                        f"[Watchdog] INTELLIGENCE INTEGRITY TAMPERING DETECTED: {iig_verdict.error_message}. "
                        f"Safe Mode Active={iig_verdict.safe_mode_active}"
                    )
                    intel_alert = SecurityAlert(
                        severity=AlertSeverity.CRITICAL,
                        category=AlertCategory.INTELLIGENCE_TAMPERING,
                        source="watchdog.intelligence_guard",
                        message=f"Intelligence integrity violation detected: {iig_verdict.error_message}",
                        details={
                            "failed_assets": iig_verdict.failed_assets,
                            "anomalies": iig_verdict.anomalies,
                            "safe_mode_active": iig_verdict.safe_mode_active,
                        },
                    )
                    await self.broadcast_alert(intel_alert)

                    # Trigger Autonomous Response Controller (ARC) Fallback
                    try:
                        from backend.self_defense.response_controller import response_controller
                        await response_controller.handle_intelligence_tampering(
                            iig_verdict=iig_verdict,
                            source="watchdog.intelligence_guard"
                        )
                    except Exception as arc_ex:
                        logger.error(f"[Watchdog] Failed to trigger ARC on intelligence tampering: {arc_ex}")
            except Exception as iex:
                logger.error(f"[Watchdog] Error during intelligence integrity sweep: {iex}", exc_info=True)

            # Step 4: Sensor Trust Integrity Sweep (Stage 2 Step 6)
            try:
                from backend.database.collections import sensors_repo
                from backend.self_defense.sensor_trust import sensor_trust_engine
                from backend.self_defense.response_controller import response_controller

                all_sensors = await sensors_repo.list({}, limit=50)
                for s in all_sensors:
                    s_id = s.get("sensor_id")
                    t_id = s.get("tenant_id", "default")
                    if s_id:
                        score_obj = await sensor_trust_engine.get_or_create_trust_score(s_id, t_id)
                        if score_obj.trust_score < 0.50 and not await response_controller.is_sensor_contained(s_id, t_id):
                            await response_controller.handle_trust_collapse(
                                sensor_id=s_id,
                                tenant_id=t_id,
                                trust_score=score_obj.trust_score,
                                reason="Watchdog sweep detected uncontained sensor with collapsed trust score (<0.50)",
                            )
            except Exception as swe:
                logger.debug(f"[Watchdog] Sensor trust sweep note: {swe}")

            return result

        except AuditStorageError as ase:
            self.last_result = AuditVerificationResult(
                is_valid=False,
                error_message=f"Storage error during verification: {ase}",
            )
            storage_alert = SecurityAlert(
                severity=AlertSeverity.CRITICAL,
                category=AlertCategory.STORAGE_FAILURE,
                source="watchdog.chain_verifier",
                message=f"Cannot verify audit integrity due to storage error: {ase}",
                details={"error": str(ase)},
            )
            await self.broadcast_alert(storage_alert)
            return self.last_result

        except Exception as ex:
            logger.error(f"[Watchdog] Unexpected exception during audit sweep: {ex}", exc_info=True)
            unknown_alert = SecurityAlert(
                severity=AlertSeverity.HIGH,
                category=AlertCategory.INTEGRITY_VIOLATION,
                source="watchdog.sweeper",
                message=f"Watchdog sweep encountered unexpected error: {ex}",
                details={"error": str(ex)},
            )
            await self.broadcast_alert(unknown_alert)
            return AuditVerificationResult(
                is_valid=False,
                error_message=f"Unexpected error: {ex}",
            )

    async def start(self) -> None:
        """
        Starts the watchdog daemon loop. Runs continuously until stop() is called.
        """
        self._running = True
        self._stop_event.clear()
        logger.info(f"[Watchdog] Starting Independent Security Watchdog (Interval: {self.interval_seconds}s)...")

        # Initial immediate sweep on boot
        await self.run_sweep()

        while self._running:
            try:
                # Wait for interval or until stopped early
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.interval_seconds)
                # If _stop_event was set, loop will exit
                break
            except asyncio.TimeoutError:
                # Interval elapsed -> run next sweep
                if self._running:
                    await self.run_sweep()

        logger.info("[Watchdog] Independent Security Watchdog stopped.")

    def stop(self) -> None:
        """Signals the watchdog loop to terminate gracefully."""
        self._running = False
        self._stop_event.set()


# ==============================================================================
# Standalone Process CLI Entrypoint
# ==============================================================================

def main():
    """
    CLI Entrypoint for running the Watchdog as an isolated, independent process:
        python -m backend.self_defense.watchdog --run-once
        python -m backend.self_defense.watchdog --interval 30 --alert-file /var/log/alerts.jsonl
    """
    parser = argparse.ArgumentParser(description="NetrIQ Independent Security Watchdog")
    parser.add_argument("--interval", type=float, default=DEFAULT_SWEEP_INTERVAL, help="Sweep interval in seconds")
    parser.add_argument("--alert-file", type=str, default=DEFAULT_ALERT_FILE, help="Path to out-of-band alert log")
    parser.add_argument("--run-once", action="store_true", help="Run a single integrity sweep and exit with code")
    args = parser.parse_args()

    # Configure logging
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='{"time": "%(asctime)s", "level": "%(levelname)s", "name": "%(name)s", "message": "%(message)s"}'
    )

    alert_sink = FileAlertSink(file_path=args.alert_file)
    watchdog = IndependentSecurityWatchdog(
        alert_sinks=[alert_sink],
        interval_seconds=args.interval,
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    if args.run_once:
        print("[Watchdog CLI] Running single integrity sweep...")
        result = loop.run_until_complete(watchdog.run_sweep())
        print(f"[Watchdog CLI] Verification Result: valid={result.is_valid}, records={result.total_records}, anchors={result.verified_anchors}")
        if result.is_valid:
            sys.exit(0)
        else:
            print(f"[Watchdog CLI] TAMPER DETECTED: {result.error_message}", file=sys.stderr)
            sys.exit(1)

    # Long-running process mode with graceful signal handling
    def _sig_handler():
        print("[Watchdog CLI] Termination signal received. Stopping...")
        watchdog.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _sig_handler)
        except NotImplementedError:
            # Windows signal handlers
            signal.signal(sig, lambda s, f: _sig_handler())

    try:
        loop.run_until_complete(watchdog.start())
    finally:
        loop.close()


if __name__ == "__main__":
    main()
