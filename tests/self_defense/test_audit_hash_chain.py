"""
tests/self_defense/test_audit_hash_chain.py

Adversarial test suite for Cryptographically Sealed Audit Ledger (Stage 2 Step 1).
Validates:
1. Sequential integrity and cryptographic hash chaining.
2. Adversarial content modification detection.
3. Adversarial record deletion detection.
4. Adversarial record insertion detection.
5. Adversarial record reordering detection.
6. Full-chain recalculation attack detection via external anchors.
7. Backend restart and persistence continuity.
8. Audit storage failure handling.
"""

import os
import shutil
import tempfile
import pytest
import asyncio
from pathlib import Path

from backend.database.in_memory_db import InMemoryDatabase
from backend.database.collections import BaseRepository
from backend.self_defense.schemas import TamperType
from backend.self_defense.audit_ledger import (
    CryptographicallySealedAuditLedger,
    ExternalAnchorStore,
    AuditStorageError,
)


@pytest.fixture
def temp_dir():
    temp_path = Path(tempfile.mkdtemp(prefix="netriq_audit_test_"))
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

        async def delete(self, doc_id: str):
            await self.collection.delete_one({"_id": doc_id})

    return MockAuditRepo(mock_db)


@pytest.fixture
def anchor_store(temp_dir):
    return ExternalAnchorStore(temp_dir / "anchors.jsonl")


@pytest.fixture
def ledger(mock_repo, anchor_store):
    return CryptographicallySealedAuditLedger(
        repository=mock_repo,
        anchor_store=anchor_store,
        signing_key="test_isolated_signing_key_12345!",
        anchor_frequency=5,  # Anchor every 5 records for fast testing
    )


# ==============================================================================
# Test Cases
# ==============================================================================

@pytest.mark.asyncio
async def test_normal_chain_creation_and_external_anchors(ledger, anchor_store):
    """Verify clean ledger creation, sequence ordering, and external anchoring."""
    # Append 12 records
    for i in range(1, 13):
        rec = await ledger.append_entry(
            action=f"ACTION_{i}",
            resource_type="sensor",
            resource_id=f"sensor-{i}",
            tenant_id="tenant_alpha",
            details={"index": i, "data": "clean"},
        )
        assert rec.sequence_number == i
        assert len(rec.entry_hash) == 64
        assert len(rec.signature) == 64

    # Verification must pass cleanly
    verdict = await ledger.verify_integrity()
    assert verdict.is_valid is True
    assert verdict.total_records == 12
    # With anchor_frequency=5, anchors should exist for seq=5 and seq=10
    assert verdict.verified_anchors == 2
    assert verdict.tamper_detected is False

    anchors = await anchor_store.load_anchors()
    assert len(anchors) == 2
    assert anchors[0].sequence_number == 5
    assert anchors[1].sequence_number == 10


@pytest.mark.asyncio
async def test_adversarial_record_content_modification(ledger, mock_db):
    """
    Simulate an attacker directly mutating a record's details in the database.
    The ledger must detect content tampering via hash mismatch.
    """
    for i in range(1, 8):
        await ledger.append_entry(
            action=f"CONFIG_CHANGE_{i}",
            resource_type="config",
            resource_id="setting_01",
            details={"val": i},
        )

    # Attack: Mutate record sequence 4 in the underlying database
    raw_docs = mock_db["audit_logs"]._docs
    target_doc = next(d for d in raw_docs if d["sequence_number"] == 4)
    target_doc["details"]["val"] = 999  # Tampered value!

    verdict = await ledger.verify_integrity()
    assert verdict.is_valid is False
    assert verdict.tamper_detected is True
    assert verdict.tamper_type == TamperType.MODIFIED
    assert verdict.tampered_sequence == 4
    assert "Tampered content at seq=4" in verdict.error_message


@pytest.mark.asyncio
async def test_adversarial_record_deletion(ledger, mock_db):
    """
    Simulate an attacker deleting an intermediate record to hide evidence.
    The ledger must detect the sequence gap.
    """
    for i in range(1, 8):
        await ledger.append_entry(
            action=f"SEVERITY_OVERRIDE_{i}",
            resource_type="incident",
            resource_id=f"inc_{i}",
        )

    # Attack: Remove record sequence 4 from database
    mock_db["audit_logs"]._docs = [
        d for d in mock_db["audit_logs"]._docs if d["sequence_number"] != 4
    ]

    verdict = await ledger.verify_integrity()
    assert verdict.is_valid is False
    assert verdict.tamper_detected is True
    assert verdict.tamper_type == TamperType.DELETED
    assert verdict.tampered_sequence == 4
    assert "Sequence gap" in verdict.error_message


@pytest.mark.asyncio
async def test_adversarial_record_insertion(ledger, mock_db):
    """
    Simulate an attacker injecting a forged record into the chain.
    The ledger must detect duplicate/injected sequence or broken chain.
    """
    for i in range(1, 6):
        await ledger.append_entry(
            action=f"AUDIT_{i}",
            resource_type="user",
            resource_id=f"u_{i}",
        )

    # Attack: Inject a duplicate sequence number 3 with forged action
    forged_entry = dict(mock_db["audit_logs"]._docs[2])
    forged_entry["_id"] = "forged_id_999"
    forged_entry["entry_id"] = "forged_uuid_999"
    forged_entry["action"] = "ROGUE_ADMIN_INJECTION"
    mock_db["audit_logs"]._docs.insert(3, forged_entry)

    verdict = await ledger.verify_integrity()
    assert verdict.is_valid is False
    assert verdict.tamper_detected is True
    assert verdict.tamper_type in (TamperType.REORDERED, TamperType.MODIFIED)


@pytest.mark.asyncio
async def test_adversarial_record_reordering(ledger, mock_db):
    """
    Simulate an attacker swapping the order of two events.
    The ledger must detect reordering.
    """
    for i in range(1, 6):
        await ledger.append_entry(
            action=f"ACTION_{i}",
            resource_type="rule",
            resource_id=f"rule_{i}",
        )

    # Attack: Swap the sequence numbers of record 2 and record 3
    docs = mock_db["audit_logs"]._docs
    docs[1]["sequence_number"], docs[2]["sequence_number"] = (
        docs[2]["sequence_number"],
        docs[1]["sequence_number"],
    )

    verdict = await ledger.verify_integrity()
    assert verdict.is_valid is False
    assert verdict.tamper_detected is True
    assert verdict.tamper_type in (TamperType.REORDERED, TamperType.MODIFIED)


@pytest.mark.asyncio
async def test_adversarial_full_chain_recalculation_thwarted_by_anchors(ledger, mock_db, anchor_store):
    """
    Adversarial Attack: A privileged attacker with database write access
    alters record seq=3, AND recalculates all subsequent hashes (prev_hash and entry_hash)
    up to seq=10 to forge an apparently valid hash chain.
    
    The external anchor store (anchored at seq=5 and seq=10) must detect the
    attack because the recomputed hashes will not match the external anchor checkpoints.
    """
    # Append 10 entries (anchors generated at seq=5 and seq=10)
    for i in range(1, 11):
        await ledger.append_entry(
            action=f"SENSITIVE_OP_{i}",
            resource_type="firewall",
            resource_id=f"fw_{i}",
            details={"authorized": True},
        )

    # Verify initial validity
    initial_verdict = await ledger.verify_integrity()
    assert initial_verdict.is_valid is True
    assert initial_verdict.verified_anchors == 2

    # Privileged Attacker Rewrites the Database Chain:
    raw_docs = mock_db["audit_logs"]._docs
    # 1. Tamper with record 3
    raw_docs[2]["action"] = "UNAUTHORIZED_DISABLE"
    
    # 2. Recompute the entire hash chain from record 3 to 10 using the ledger's formula
    curr_prev = raw_docs[1]["entry_hash"]
    for idx in range(2, len(raw_docs)):
        d = raw_docs[idx]
        d["prev_hash"] = curr_prev
        new_hash = ledger.compute_entry_hash(
            sequence_number=d["sequence_number"],
            timestamp=d["timestamp"],
            tenant_id=d["tenant_id"],
            actor=d["actor"],
            action=d["action"],
            resource_type=d["resource_type"],
            resource_id=d["resource_id"],
            status=d["status"],
            details=d["details"],
            prev_hash=d["prev_hash"],
        )
        d["entry_hash"] = new_hash
        d["signature"] = ledger.compute_signature(new_hash)
        curr_prev = new_hash

    # 3. If only simple hash-chaining was used, the recomputed chain would look valid.
    # But because of External Anchors, verify_integrity() must catch ANCHOR_MISMATCH!
    verdict = await ledger.verify_integrity()
    assert verdict.is_valid is False
    assert verdict.tamper_detected is True
    assert verdict.tamper_type == TamperType.ANCHOR_MISMATCH
    assert verdict.tampered_sequence == 5
    assert "External anchor mismatch at seq=5" in verdict.error_message


@pytest.mark.asyncio
async def test_backend_restart_and_continuity(mock_repo, anchor_store):
    """
    Verify that shutting down and re-instantiating the ledger resumes
    the sequence number and hash chaining seamlessly.
    """
    ledger_instance_1 = CryptographicallySealedAuditLedger(
        repository=mock_repo,
        anchor_store=anchor_store,
        anchor_frequency=5,
    )

    # 1. Write records 1 through 6
    for i in range(1, 7):
        await ledger_instance_1.append_entry(
            action=f"BOOT_ACTION_{i}",
            resource_type="system",
            resource_id="kernel",
        )

    # Simulate process termination / restart: create new instance with same stores
    ledger_instance_2 = CryptographicallySealedAuditLedger(
        repository=mock_repo,
        anchor_store=anchor_store,
        anchor_frequency=5,
    )

    # Write records 7 through 10
    for i in range(7, 11):
        rec = await ledger_instance_2.append_entry(
            action=f"REBOOT_ACTION_{i}",
            resource_type="system",
            resource_id="kernel",
        )
        assert rec.sequence_number == i

    # Entire chain (1..10) must be 100% valid
    verdict = await ledger_instance_2.verify_integrity()
    assert verdict.is_valid is True
    assert verdict.total_records == 10
    assert verdict.verified_anchors == 2  # anchored at 5 and 10


@pytest.mark.asyncio
async def test_audit_storage_failure_handling(anchor_store):
    """
    Verify that database failure raises AuditStorageError and preserves
    state without corrupting sequence counters.
    """
    class BrokenRepository:
        async def list(self, *args, **kwargs):
            return []

        async def create(self, data):
            raise ConnectionError("Simulated Database IO Failure")

    broken_ledger = CryptographicallySealedAuditLedger(
        repository=BrokenRepository(),
        anchor_store=anchor_store,
    )

    with pytest.raises(AuditStorageError) as exc_info:
        await broken_ledger.append_entry(
            action="FAILING_ACTION",
            resource_type="test",
            resource_id="t1",
        )

    assert "Database write failed" in str(exc_info.value)
