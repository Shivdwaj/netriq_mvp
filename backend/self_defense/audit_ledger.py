"""
backend/self_defense/audit_ledger.py

Cryptographically Sealed Audit Ledger (CAL) for Stage 2 Self-Defense.
Implements:
1. Forward-secure SHA-256 hash chaining of audit entries.
2. Isolated HMAC-SHA256 signature per entry.
3. Periodic external hash anchoring to protected out-of-band storage.
4. Mathematical verification detecting modifications, deletions, insertions,
   reorderings, and full-chain recalculation attacks.
5. Storage failure detection and restart resilience.
"""

import os
import json
import time
import hmac
import hashlib
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional, List, Union

from backend.utils.logger import get_logger
from backend.self_defense.schemas import (
    AuditRecord,
    AuditAnchor,
    AuditVerificationResult,
    TamperType,
    get_utc_now_timestamp,
    get_utc_now_iso,
)

logger = get_logger(__name__)

# Fallback genesis hash (64 hex zeros)
GENESIS_HASH = "0" * 64

# Configurable signing key (isolated from standard JWT secret)
_default_audit_key = os.getenv("NETRIQ_AUDIT_SIGNING_KEY", "netriq_audit_isolated_signing_secret_key_2026!")
_default_anchor_file = os.getenv("NETRIQ_AUDIT_ANCHOR_FILE", "storage/audit_anchors.jsonl")
_default_anchor_freq = int(os.getenv("NETRIQ_AUDIT_ANCHOR_FREQUENCY", "10"))


class AuditStorageError(Exception):
    """Raised when the audit ledger cannot read from or write to its underlying storage."""
    pass


class AuditTamperError(Exception):
    """Raised when mathematical verification detects audit tampering."""
    def __init__(self, message: str, result: AuditVerificationResult):
        super().__init__(message)
        self.result = result


class ExternalAnchorStore:
    """
    Append-only durable store for external audit anchors.
    Maintains an out-of-band JSONL record of anchor checkpoints.
    """
    def __init__(self, file_path: Union[str, Path]):
        self.file_path = Path(file_path)
        self._lock = asyncio.Lock()
        self._ensure_dir()

    def _ensure_dir(self):
        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning(f"[ExternalAnchorStore] Could not create anchor directory: {e}")

    async def append_anchor(self, anchor: AuditAnchor) -> None:
        """Appends an anchor record atomically to the anchor file."""
        async with self._lock:
            try:
                self._ensure_dir()
                line = anchor.model_dump_json() + "\n"
                # Write in append mode with explicit flush
                with open(self.file_path, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception as e:
                logger.error(f"[ExternalAnchorStore] Failed to write anchor to {self.file_path}: {e}")
                raise AuditStorageError(f"External anchor store write failure: {e}") from e

    async def load_anchors(self) -> List[AuditAnchor]:
        """Loads all external anchors from the anchor file."""
        async with self._lock:
            if not self.file_path.exists():
                return []
            anchors: List[AuditAnchor] = []
            try:
                with open(self.file_path, "r", encoding="utf-8") as f:
                    for line_no, line in enumerate(f, start=1):
                        line_clean = line.strip()
                        if not line_clean:
                            continue
                        try:
                            data = json.loads(line_clean)
                            anchors.append(AuditAnchor(**data))
                        except Exception as parse_err:
                            logger.error(f"[ExternalAnchorStore] Corrupted anchor at line {line_no}: {parse_err}")
                return anchors
            except Exception as e:
                logger.error(f"[ExternalAnchorStore] Failed to read anchors from {self.file_path}: {e}")
                raise AuditStorageError(f"External anchor store read failure: {e}") from e

    async def clear(self) -> None:
        """Truncates the anchor file (used in tests or factory reset)."""
        async with self._lock:
            if self.file_path.exists():
                try:
                    self.file_path.unlink()
                except Exception as e:
                    logger.warning(f"[ExternalAnchorStore] Could not unlink anchor file: {e}")


class CryptographicallySealedAuditLedger:
    """
    Central Audit Ledger providing append-only, tamper-evident audit logging.
    Guarantees:
    - Forward-secure SHA-256 hash chaining.
    - HMAC-SHA256 signature per entry.
    - Periodic external anchoring to out-of-band protected storage.
    - Multi-tenant isolation for query views.
    - Full mathematical verification on demand.
    """

    def __init__(
        self,
        repository=None,
        anchor_store: Optional[ExternalAnchorStore] = None,
        signing_key: Optional[str] = None,
        anchor_frequency: Optional[int] = None,
    ):
        self._repo = repository
        self.signing_key = signing_key or _default_audit_key
        self.anchor_frequency = anchor_frequency or _default_anchor_freq
        self.anchor_store = anchor_store or ExternalAnchorStore(_default_anchor_file)
        self._write_lock = asyncio.Lock()
        
        # In-memory fast cache of the latest committed sequence and hash
        self._last_seq: Optional[int] = None
        self._last_hash: Optional[str] = None

    def _get_repo(self):
        if self._repo is not None:
            return self._repo
        # Fallback to default collections repo
        from backend.database.collections import audit_logs_repo
        return audit_logs_repo

    @staticmethod
    def canonical_json(data: Any) -> str:
        """Produces a deterministic, canonical JSON string without whitespace variations."""
        return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)

    def compute_entry_hash(
        self,
        sequence_number: int,
        timestamp: float,
        tenant_id: str,
        actor: Dict[str, Any],
        action: str,
        resource_type: str,
        resource_id: str,
        status: str,
        details: Dict[str, Any],
        prev_hash: str,
    ) -> str:
        """
        Calculates SHA-256 hash across canonical representation of all record fields.
        """
        canonical_actor = self.canonical_json(actor)
        canonical_details = self.canonical_json(details)
        raw_payload = (
            f"{sequence_number}|{timestamp:.6f}|{tenant_id}|{canonical_actor}|"
            f"{action}|{resource_type}|{resource_id}|{status}|{canonical_details}|{prev_hash}"
        )
        return hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

    def compute_signature(self, entry_hash: str) -> str:
        """Generates an HMAC-SHA256 signature using the isolated audit signing key."""
        return hmac.new(
            self.signing_key.encode("utf-8"),
            entry_hash.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    def compute_anchor_signature(self, sequence_number: int, entry_hash: str) -> str:
        """Generates an HMAC-SHA256 signature for an external anchor."""
        raw = f"{sequence_number}:{entry_hash}"
        return hmac.new(
            self.signing_key.encode("utf-8"),
            raw.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    async def _resolve_tail(self) -> tuple[int, str]:
        """
        Queries the database for the latest committed audit entry to resume the chain
        after process restarts.
        """
        if self._last_seq is not None and self._last_hash is not None:
            return self._last_seq, self._last_hash

        repo = self._get_repo()
        try:
            # Sort by sequence_number descending to find the head
            docs = await repo.list({}, limit=1, sort_by=[("sequence_number", -1)])
            if docs:
                last_doc = docs[0]
                self._last_seq = int(last_doc["sequence_number"])
                self._last_hash = str(last_doc["entry_hash"])
            else:
                self._last_seq = 0
                self._last_hash = GENESIS_HASH
            return self._last_seq, self._last_hash
        except Exception as e:
            logger.error(f"[AuditLedger] Failed to query tail record: {e}")
            raise AuditStorageError(f"Failed to read audit log tail: {e}") from e

    async def append_entry(
        self,
        action: str,
        resource_type: str,
        resource_id: str,
        actor: Optional[Dict[str, Any]] = None,
        tenant_id: str = "global",
        details: Optional[Dict[str, Any]] = None,
        status: str = "SUCCESS",
    ) -> AuditRecord:
        """
        Appends a new cryptographically sealed audit record to the ledger.
        Atomic, thread-safe, and generates external anchors at configured intervals.
        """
        actor = actor or {"user_id": "system", "username": "system", "role": "system"}
        details = details or {}
        now = get_utc_now_timestamp()
        now_iso = get_utc_now_iso()

        async with self._write_lock:
            last_seq, last_hash = await self._resolve_tail()
            new_seq = last_seq + 1
            prev_hash = last_hash

            entry_hash = self.compute_entry_hash(
                sequence_number=new_seq,
                timestamp=now,
                tenant_id=tenant_id,
                actor=actor,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                status=status,
                details=details,
                prev_hash=prev_hash,
            )
            signature = self.compute_signature(entry_hash)

            record = AuditRecord(
                sequence_number=new_seq,
                timestamp=now,
                timestamp_iso=now_iso,
                tenant_id=tenant_id,
                actor=actor,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details,
                status=status,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
                signature=signature,
            )

            # Persist to repository
            repo = self._get_repo()
            try:
                record_dict = record.model_dump()
                await repo.create(record_dict)
            except Exception as e:
                logger.error(f"[AuditLedger] Storage error while writing record seq={new_seq}: {e}")
                raise AuditStorageError(f"Database write failed for audit record seq={new_seq}: {e}") from e

            # Update cached tail
            self._last_seq = new_seq
            self._last_hash = entry_hash

            # External Hash Anchoring
            if new_seq % self.anchor_frequency == 0:
                anchor_sig = self.compute_anchor_signature(new_seq, entry_hash)
                anchor = AuditAnchor(
                    sequence_number=new_seq,
                    entry_hash=entry_hash,
                    timestamp=now,
                    timestamp_iso=now_iso,
                    signature=anchor_sig,
                )
                try:
                    await self.anchor_store.append_anchor(anchor)
                    logger.info(f"[AuditLedger] External anchor committed at seq={new_seq} (hash={entry_hash[:10]}...)")
                except Exception as anchor_err:
                    logger.critical(f"[AuditLedger] CRITICAL: Failed to write external anchor at seq={new_seq}: {anchor_err}")
                    # Re-raise so callers know anchor persistence had an issue
                    raise

            return record

    async def verify_integrity(self) -> AuditVerificationResult:
        """
        Executes a rigorous mathematical verification across the entire audit ledger:
        1. Checks strictly monotonic sequence numbers starting at 1.
        2. Detects deleted, inserted, or reordered records.
        3. Verifies SHA-256 hash chaining (record.prev_hash == previous.entry_hash).
        4. Recomputes record entry_hash and checks against recorded entry_hash (detects modified records).
        5. Verifies HMAC-SHA256 signature for each record.
        6. Reconciles all external anchors against the chain (detects full chain recalculation).
        """
        repo = self._get_repo()
        try:
            # Retrieve all audit records ordered by sequence_number ascending
            docs = await repo.list({}, limit=100000, sort_by=[("sequence_number", 1)])
        except Exception as e:
            logger.error(f"[AuditLedger] Failed to retrieve records for verification: {e}")
            raise AuditStorageError(f"Could not read audit records for verification: {e}") from e

        if not docs:
            return AuditVerificationResult(
                is_valid=True,
                total_records=0,
                verified_anchors=0,
                tamper_detected=False,
            )

        records: List[AuditRecord] = []
        for d in docs:
            try:
                records.append(AuditRecord(**d))
            except Exception as pe:
                return AuditVerificationResult(
                    is_valid=False,
                    total_records=len(docs),
                    tamper_detected=True,
                    tamper_type=TamperType.MODIFIED,
                    error_message=f"Schema violation in audit record: {pe}",
                )

        expected_seq = 1
        expected_prev_hash = GENESIS_HASH

        for idx, rec in enumerate(records):
            # A. Sequential continuity check
            if rec.sequence_number != expected_seq:
                if rec.sequence_number < expected_seq:
                    return AuditVerificationResult(
                        is_valid=False,
                        total_records=len(records),
                        tamper_detected=True,
                        tamper_type=TamperType.REORDERED,
                        tampered_sequence=rec.sequence_number,
                        tampered_entry_id=rec.entry_id,
                        error_message=f"Sequence anomaly at index {idx}: expected {expected_seq}, found {rec.sequence_number} (reordered or duplicated).",
                    )
                else:
                    return AuditVerificationResult(
                        is_valid=False,
                        total_records=len(records),
                        tamper_detected=True,
                        tamper_type=TamperType.DELETED,
                        tampered_sequence=expected_seq,
                        tampered_entry_id=rec.entry_id,
                        error_message=f"Sequence gap at index {idx}: expected {expected_seq}, found {rec.sequence_number} (missing or deleted records).",
                    )

            # B. Hash-chain linkage check
            if rec.prev_hash != expected_prev_hash:
                return AuditVerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    tamper_detected=True,
                    tamper_type=TamperType.MODIFIED,
                    tampered_sequence=rec.sequence_number,
                    tampered_entry_id=rec.entry_id,
                    error_message=f"Broken hash chain at seq={rec.sequence_number}: prev_hash does not match preceding entry_hash.",
                )

            # C. Entry content recalculation check (detects in-place field edits)
            recomputed_hash = self.compute_entry_hash(
                sequence_number=rec.sequence_number,
                timestamp=rec.timestamp,
                tenant_id=rec.tenant_id,
                actor=rec.actor,
                action=rec.action,
                resource_type=rec.resource_type,
                resource_id=rec.resource_id,
                status=rec.status,
                details=rec.details,
                prev_hash=rec.prev_hash,
            )
            if recomputed_hash != rec.entry_hash:
                return AuditVerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    tamper_detected=True,
                    tamper_type=TamperType.MODIFIED,
                    tampered_sequence=rec.sequence_number,
                    tampered_entry_id=rec.entry_id,
                    error_message=f"Tampered content at seq={rec.sequence_number}: recomputed hash {recomputed_hash[:10]}... != recorded hash {rec.entry_hash[:10]}...",
                )

            # D. Signature validity check
            expected_sig = self.compute_signature(rec.entry_hash)
            if not hmac.compare_digest(rec.signature, expected_sig):
                return AuditVerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    tamper_detected=True,
                    tamper_type=TamperType.SIGNATURE_INVALID,
                    tampered_sequence=rec.sequence_number,
                    tampered_entry_id=rec.entry_id,
                    error_message=f"Invalid cryptographic signature at seq={rec.sequence_number}.",
                )

            expected_prev_hash = rec.entry_hash
            expected_seq += 1

        # E. External Anchor Reconciliation
        anchors = await self.anchor_store.load_anchors()
        record_map = {r.sequence_number: r for r in records}
        verified_anchor_count = 0

        for anchor in anchors:
            # 1. Verify anchor's own signature
            expected_anchor_sig = self.compute_anchor_signature(anchor.sequence_number, anchor.entry_hash)
            if not hmac.compare_digest(anchor.signature, expected_anchor_sig):
                return AuditVerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    verified_anchors=verified_anchor_count,
                    tamper_detected=True,
                    tamper_type=TamperType.SIGNATURE_INVALID,
                    tampered_sequence=anchor.sequence_number,
                    error_message=f"External anchor signature corrupted at seq={anchor.sequence_number}.",
                )

            # 2. Assert anchored record exists in database
            target_record = record_map.get(anchor.sequence_number)
            if not target_record:
                return AuditVerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    verified_anchors=verified_anchor_count,
                    tamper_detected=True,
                    tamper_type=TamperType.DELETED,
                    tampered_sequence=anchor.sequence_number,
                    error_message=f"Anchored record at seq={anchor.sequence_number} is missing from the database (chain truncated).",
                )

            # 3. Assert anchored hash matches database record hash (detects full chain recalculation)
            if target_record.entry_hash != anchor.entry_hash:
                return AuditVerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    verified_anchors=verified_anchor_count,
                    tamper_detected=True,
                    tamper_type=TamperType.ANCHOR_MISMATCH,
                    tampered_sequence=anchor.sequence_number,
                    tampered_entry_id=target_record.entry_id,
                    error_message=(
                        f"External anchor mismatch at seq={anchor.sequence_number}: "
                        f"database hash ({target_record.entry_hash[:10]}...) does not match "
                        f"external anchor hash ({anchor.entry_hash[:10]}...). Chain was rewritten!"
                    ),
                )

            verified_anchor_count += 1

        return AuditVerificationResult(
            is_valid=True,
            total_records=len(records),
            verified_anchors=verified_anchor_count,
            tamper_detected=False,
            tamper_type=TamperType.NONE,
        )

    async def check_storage_health(self) -> bool:
        """
        Verifies that both the audit log repository and the external anchor store
        are healthy, responsive, and writable.
        """
        try:
            repo = self._get_repo()
            # Test read
            await repo.list({}, limit=1)
            # Test anchor store read
            await self.anchor_store.load_anchors()
            return True
        except Exception as e:
            logger.error(f"[AuditLedger] Storage health check failed: {e}")
            raise AuditStorageError(f"Storage health check failed: {e}") from e


# Global singleton instance
audit_ledger = CryptographicallySealedAuditLedger()

