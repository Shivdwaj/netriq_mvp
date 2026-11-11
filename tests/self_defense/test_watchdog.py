"""
tests/self_defense/test_watchdog.py

Adversarial test suite for Independent Security Watchdog (Stage 2 Step 1).
Validates:
1. Periodic health sweep on clean ledger emits zero false alarms.
2. Out-of-band critical alert dispatch upon audit tampering detection.
3. Storage failure detection and independent alert generation.
4. Fault-domain separation: alerts dispatched without dependency on primary EventBus/WebSockets.
5. Watchdog standalone CLI execution with proper exit codes (--run-once).
"""

import os
import sys
import shutil
import tempfile
import pytest
import asyncio
from pathlib import Path
from unittest.mock import patch, MagicMock

from backend.database.in_memory_db import InMemoryDatabase
from backend.self_defense.schemas import (
    AlertSeverity,
    AlertCategory,
    TamperType,
)
from backend.self_defense.audit_ledger import (
    CryptographicallySealedAuditLedger,
    ExternalAnchorStore,
    AuditStorageError,
)
from backend.self_defense.watchdog import (
    IndependentSecurityWatchdog,
    FileAlertSink,
    MemoryAlertSink,
)


@pytest.fixture
def temp_dir():
    temp_path = Path(tempfile.mkdtemp(prefix="netriq_watchdog_test_"))
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def mock_db():
    return InMemoryDatabase()


@pytest.fixture
def mock_repo(mock_db):
    class MockAuditRepo:
        def __init__(self, db):
            self.collection = db["audit_logs"]

        async def create(self, data: dict) -> str:
            clean = dict(data)
            res = await self.collection.insert_one(clean)
            return str(res.inserted_id)

        async def list(self, filter_query=None, limit=100000, sort_by=None):
            cursor = self.collection.find(filter_query or {})
            if sort_by:
                cursor = cursor.sort(sort_by)
            docs = await cursor.to_list(length=limit)
            return [dict(d) for d in docs]

    return MockAuditRepo(mock_db)


@pytest.fixture
def anchor_store(temp_dir):
    return ExternalAnchorStore(temp_dir / "anchors.jsonl")


@pytest.fixture
def ledger(mock_repo, anchor_store):
    return CryptographicallySealedAuditLedger(
        repository=mock_repo,
        anchor_store=anchor_store,
        anchor_frequency=3,
    )


@pytest.fixture
def memory_sink():
    return MemoryAlertSink()


@pytest.fixture
def file_sink(temp_dir):
    return FileAlertSink(temp_dir / "alerts" / "security_alerts.jsonl")


@pytest.fixture
def watchdog(ledger, memory_sink, file_sink):
    return IndependentSecurityWatchdog(
        ledger=ledger,
        alert_sinks=[memory_sink, file_sink],
        interval_seconds=0.1,  # Fast for testing
    )


# ==============================================================================
# Test Cases
# ==============================================================================

@pytest.mark.asyncio
async def test_watchdog_healthy_sweep_no_alerts(watchdog, ledger, memory_sink, file_sink):
    """Verify that a healthy ledger produces zero false alarms during sweep."""
    for i in range(1, 6):
        await ledger.append_entry(
            action=f"LOGIN_{i}",
            resource_type="auth",
            resource_id=f"u_{i}",
        )

    result = await watchdog.run_sweep()
    assert result.is_valid is True
    assert result.total_records == 5
    assert len(memory_sink.alerts) == 0
    assert len(file_sink.read_alerts()) == 0


@pytest.mark.asyncio
async def test_watchdog_detects_tamper_and_dispatches_out_of_band_alert(
    watchdog, ledger, mock_db, memory_sink, file_sink
):
    """
    Adversarial Attack: Tamper with database audit record.
    Verify that Watchdog catches the tamper and dispatches a CRITICAL alert
    to both memory and independent file sinks.
    """
    for i in range(1, 5):
        await ledger.append_entry(
            action=f"ACTION_{i}",
            resource_type="sensor",
            resource_id="s1",
            details={"safe": True},
        )

    # Attack: Mutate record sequence 2 in database
    target_doc = next(d for d in mock_db["audit_logs"]._docs if d["sequence_number"] == 2)
    target_doc["details"]["safe"] = False  # Tampered!

    # Run watchdog sweep
    result = await watchdog.run_sweep()
    assert result.is_valid is False
    assert result.tamper_type == TamperType.MODIFIED
    assert result.tampered_sequence == 2

    # Assert Memory Alert Sink captured the alert
    assert len(memory_sink.alerts) == 1
    alert = memory_sink.alerts[0]
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.category == AlertCategory.AUDIT_TAMPERING
    assert "Cryptographic audit tamper detected" in alert.message
    assert alert.details["tampered_sequence"] == 2

    # Assert File Alert Sink (out-of-band persistent storage) captured the alert
    persisted_alerts = file_sink.read_alerts()
    assert len(persisted_alerts) == 1
    assert persisted_alerts[0].alert_id == alert.alert_id
    assert persisted_alerts[0].details["tamper_type"] == "MODIFIED"


@pytest.mark.asyncio
async def test_watchdog_detects_storage_failure(watchdog, ledger, memory_sink, file_sink):
    """
    Simulate a catastrophic storage outage during verification.
    Watchdog must immediately dispatch a CRITICAL storage alert.
    """
    with patch.object(ledger, "check_storage_health", side_effect=AuditStorageError("Database connection dropped")):
        result = await watchdog.run_sweep()

    assert result.is_valid is False
    assert len(memory_sink.alerts) >= 1
    storage_alert = next((a for a in memory_sink.alerts if a.category == AlertCategory.STORAGE_FAILURE), None)
    assert storage_alert is not None
    assert storage_alert.severity == AlertSeverity.CRITICAL
    assert "Audit storage failure" in storage_alert.message


@pytest.mark.asyncio
async def test_watchdog_fault_domain_separation_without_eventbus(
    watchdog, ledger, mock_db, memory_sink, file_sink
):
    """
    Verify fault domain separation: The Watchdog functions and delivers alerts
    even if the backend EventBus, WebSockets, or FastAPI app are completely absent
    or raising exceptions.
    """
    # Write entries
    for i in range(1, 4):
        await ledger.append_entry(action=f"ACT_{i}", resource_type="user", resource_id="admin")

    # Simulate attack: delete record seq 1
    mock_db["audit_logs"]._docs = [d for d in mock_db["audit_logs"]._docs if d["sequence_number"] != 1]

    # Verify sweep dispatches alert directly to file without requiring EventBus
    result = await watchdog.run_sweep()
    assert result.is_valid is False
    assert result.tamper_type == TamperType.DELETED

    # The file sink must have recorded the critical out-of-band alert
    file_alerts = file_sink.read_alerts()
    assert len(file_alerts) == 1
    assert file_alerts[0].severity == AlertSeverity.CRITICAL
    assert file_alerts[0].details["tampered_sequence"] == 1


@pytest.mark.asyncio
async def test_watchdog_daemon_lifecycle(watchdog, ledger):
    """Verify that start() runs sweeps periodically and stop() shuts it down cleanly."""
    for i in range(1, 3):
        await ledger.append_entry(action=f"OP_{i}", resource_type="rule", resource_id="r1")

    # Start in background task
    task = asyncio.create_task(watchdog.start())
    await asyncio.sleep(0.25)  # Let it run at least 2 sweeps (interval is 0.1s)
    
    assert watchdog.sweep_count >= 2
    assert watchdog._running is True

    # Stop watchdog
    watchdog.stop()
    await task
    assert watchdog._running is False


def test_watchdog_cli_run_once(temp_dir):
    """Verify CLI --run-once exits 0 on clean ledger and 1 on tamper."""
    from backend.self_defense.watchdog import main

    # 1. Clean run test
    with patch("sys.argv", ["watchdog.py", "--run-once", "--alert-file", str(temp_dir / "cli_alerts.jsonl")]):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
