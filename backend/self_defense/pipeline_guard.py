"""
backend/self_defense/pipeline_guard.py

Pipeline Integrity Guard (PIG) for NetrIQ Stage 2 Self-Defense.
Implements:
1. HMAC-SHA256 payload authentication signing exact raw received bytes.
2. HKDF-SHA256 (RFC 5869) key derivation with separately protected master secret.
3. Multi-worker database-backed atomic compare-and-update sequence checks.
4. Replay attack rejection (monotonic sequence per sensor).
5. Freshness window validation (+/- 15 seconds).
6. Sequence gap detection (> 10 missing batches).
7. Key versioning and rotation support.
8. Configurable strict vs migration compatibility mode.
"""

import os
import time
import hmac
import hashlib
from typing import Dict, Any, Optional, Union, Tuple
from backend.utils.logger import get_logger
from backend.self_defense.schemas import (
    PipelineIntegrityVerdict,
    PipelineAnomalyType,
    get_utc_now_timestamp,
)

logger = get_logger(__name__)

# Configurable master secret and freshness limits
_env_name = os.getenv("ENVIRONMENT", os.getenv("ENV", "development")).lower()
_is_prod = _env_name in ("production", "prod")
_raw_master_secret = os.getenv("NETRIQ_PIPELINE_MASTER_SECRET")

if not _raw_master_secret:
    if _is_prod:
        raise RuntimeError(
            "FATAL SECURITY ERROR: NETRIQ_PIPELINE_MASTER_SECRET must be explicitly configured in production. "
            "Startup aborted to prevent pipeline forgery."
        )
    _default_master_secret = "netriq_pipeline_isolated_master_secret_2026!"
    logger.warning("SECURITY WARNING: NETRIQ_PIPELINE_MASTER_SECRET not set. Using local development fallback secret.")
else:
    _default_master_secret = _raw_master_secret

DEFAULT_FRESHNESS_WINDOW_SECONDS = float(os.getenv("NETRIQ_PIPELINE_FRESHNESS_SECONDS", "15.0"))
MAX_ALLOWED_SEQUENCE_GAP = int(os.getenv("NETRIQ_PIPELINE_MAX_GAP", "10"))
DEFAULT_STRICT_MODE = os.getenv("NETRIQ_PIPELINE_STRICT_INTEGRITY", "false").lower() in ("true", "1")


# ==============================================================================
# Exceptions
# ==============================================================================

class PipelineIntegrityError(Exception):
    """Base class for all pipeline integrity violations."""
    def __init__(self, message: str, anomaly_type: PipelineAnomalyType, status_code: int = 400):
        super().__init__(message)
        self.anomaly_type = anomaly_type
        self.status_code = status_code


class MissingIntegrityHeadersError(PipelineIntegrityError):
    def __init__(self, message: str = "Missing required pipeline integrity headers (X-Sensor-Signature, X-Sensor-Sequence, X-Sensor-Timestamp)."):
        super().__init__(message, PipelineAnomalyType.MISSING_HEADERS, status_code=401)


class InvalidSignatureError(PipelineIntegrityError):
    def __init__(self, message: str = "Invalid cryptographic signature: payload modified, key mismatch, or incorrect key version."):
        super().__init__(message, PipelineAnomalyType.INVALID_SIGNATURE, status_code=401)


class ExpiredTimestampError(PipelineIntegrityError):
    def __init__(self, message: str = "Timestamp expired: event batch timestamp is older than allowable freshness window (15s)."):
        super().__init__(message, PipelineAnomalyType.EXPIRED_TIMESTAMP, status_code=400)


class FutureTimestampError(PipelineIntegrityError):
    def __init__(self, message: str = "Future timestamp rejected: event batch timestamp is ahead of backend clock (>15s)."):
        super().__init__(message, PipelineAnomalyType.FUTURE_TIMESTAMP, status_code=400)


class ReplaySequenceError(PipelineIntegrityError):
    def __init__(self, message: str = "Replay sequence violation: sequence number has already been processed or arrived out-of-order."):
        super().__init__(message, PipelineAnomalyType.REPLAY_SEQUENCE, status_code=409)


# ==============================================================================
# HKDF-SHA256 (RFC 5869) Implementation
# ==============================================================================

def hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
    """RFC 5869 HKDF-Extract step."""
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-Expand step."""
    t = b""
    okm = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def derive_sensor_signing_key(
    master_secret: str, tenant_id: str, sensor_id: str, key_version: str = "v1"
) -> bytes:
    """
    Derives an isolated 256-bit HMAC signing key unique to a specific (tenant, sensor, version).
    Guarantees that compromising a sensor's API key does not give away its pipeline signing key.
    """
    salt = tenant_id.encode("utf-8")
    prk = hkdf_extract(salt=salt, input_key_material=master_secret.encode("utf-8"))
    info = f"netriq-pig:{sensor_id}:{key_version}".encode("utf-8")
    return hkdf_expand(prk, info, 32)


# ==============================================================================
# Pipeline Integrity Guard Engine
# ==============================================================================

class PipelineIntegrityGuard:
    """
    Pipeline Integrity Guard (PIG).
    Authenticates and serializes HTTP ingestion batches across multi-worker deployments.
    """

    def __init__(
        self,
        master_secret: Optional[str] = None,
        sequences_repo=None,
        freshness_window_seconds: float = DEFAULT_FRESHNESS_WINDOW_SECONDS,
        max_allowed_gap: int = MAX_ALLOWED_SEQUENCE_GAP,
        strict_mode: bool = DEFAULT_STRICT_MODE,
    ):
        self.master_secret = master_secret or _default_master_secret
        self._repo = sequences_repo
        self.freshness_window_seconds = freshness_window_seconds
        self.max_allowed_gap = max_allowed_gap
        self.strict_mode = strict_mode

    def _get_repo(self):
        if self._repo is not None:
            return self._repo
        from backend.database.collections import pipeline_sequences_repo
        return pipeline_sequences_repo

    def get_signing_key(self, tenant_id: str, sensor_id: str, key_version: str = "v1") -> bytes:
        """Returns the derived HMAC key for the given sensor."""
        return derive_sensor_signing_key(
            master_secret=self.master_secret,
            tenant_id=tenant_id,
            sensor_id=sensor_id,
            key_version=key_version,
        )

    @staticmethod
    def construct_envelope(sequence: int, timestamp_str: str, key_version: str, raw_body: bytes) -> bytes:
        """
        Constructs the canonical byte envelope:
        {sequence}:{timestamp_str}:{key_version}:{raw_body}
        """
        prefix = f"{sequence}:{timestamp_str}:{key_version}:".encode("utf-8")
        return prefix + raw_body

    def sign_payload(
        self,
        raw_body: bytes,
        sequence: int,
        timestamp_str: str,
        tenant_id: str,
        sensor_id: str,
        key_version: str = "v1",
    ) -> str:
        """
        Generates an HMAC-SHA256 signature for client/sensor agents.
        """
        key = self.get_signing_key(tenant_id, sensor_id, key_version)
        envelope = self.construct_envelope(sequence, timestamp_str, key_version, raw_body)
        return hmac.new(key, envelope, hashlib.sha256).hexdigest()

    def verify_signature(
        self,
        raw_body: bytes,
        signature: str,
        sequence: int,
        timestamp_str: str,
        tenant_id: str,
        sensor_id: str,
        key_version: str = "v1",
    ) -> bool:
        """
        Verifies the HMAC-SHA256 signature against exact raw received bytes.
        Uses constant-time comparison to prevent timing attacks.
        """
        expected_sig = self.sign_payload(
            raw_body=raw_body,
            sequence=sequence,
            timestamp_str=timestamp_str,
            tenant_id=tenant_id,
            sensor_id=sensor_id,
            key_version=key_version,
        )
        return hmac.compare_digest(expected_sig, signature)

    def verify_freshness(self, timestamp_str: str) -> float:
        """
        Validates that the batch was created within the freshness window (+/- 15s).
        Returns the parsed epoch timestamp on success.
        """
        try:
            ts_val = float(timestamp_str)
        except (ValueError, TypeError) as e:
            raise PipelineIntegrityError(f"Malformed timestamp header: {e}", PipelineAnomalyType.MISSING_HEADERS)

        now = get_utc_now_timestamp()
        if ts_val < (now - self.freshness_window_seconds):
            raise ExpiredTimestampError(
                f"Timestamp {ts_val:.2f} is older than freshness window ({self.freshness_window_seconds}s vs now {now:.2f})."
            )
        if ts_val > (now + self.freshness_window_seconds):
            raise FutureTimestampError(
                f"Timestamp {ts_val:.2f} is in the future beyond allowable skew ({self.freshness_window_seconds}s vs now {now:.2f})."
            )
        return ts_val

    async def verify_and_advance_sequence_atomic(
        self, tenant_id: str, sensor_id: str, sequence: int, timestamp: float
    ) -> Tuple[bool, int]:
        """
        Performs an atomic, database-backed compare-and-update on the monotonic sequence.
        Returns: (gap_detected: bool, gap_size: int)
        Raises ReplaySequenceError if sequence <= current_last_sequence or on concurrent collision.
        """
        if sequence < 1:
            raise ReplaySequenceError(f"Sequence number must be a positive integer (received {sequence}).")

        composite_key = f"{tenant_id}:{sensor_id}"
        repo = self._get_repo()
        collection = repo.collection
        now = get_utc_now_timestamp()

        # Step 1: Query current sequence record
        existing = await collection.find_one({"_id": composite_key})

        if existing is None:
            # First sequence for this sensor: insert atomically
            try:
                await collection.insert_one({
                    "_id": composite_key,
                    "tenant_id": tenant_id,
                    "sensor_id": sensor_id,
                    "last_sequence": sequence,
                    "last_timestamp": timestamp,
                    "updated_at": now,
                })
                # First sequence initialized cleanly
                gap_detected = sequence > 1
                gap_size = sequence - 1 if gap_detected else 0
                return gap_detected, gap_size
            except Exception:
                # Concurrent worker inserted simultaneously; re-fetch
                existing = await collection.find_one({"_id": composite_key})
                if existing is None:
                    raise ReplaySequenceError("Concurrent sequence initialization conflict.")

        current_last_seq = int(existing.get("last_sequence", 0))

        # Step 2: Monotonic Sequence Invariant Check
        if sequence <= current_last_seq:
            if sequence == current_last_seq:
                logger.warning(f"[PipelineGuard] Replay attack detected: duplicate sequence={sequence} for {composite_key}")
                raise ReplaySequenceError(
                    f"Duplicate sequence number {sequence} rejected: batch has already been processed (anti-replay)."
                )
            else:
                logger.warning(f"[PipelineGuard] Out-of-order sequence={sequence} < current={current_last_seq} for {composite_key}")
                raise ReplaySequenceError(
                    f"Out-of-order sequence {sequence} rejected: current committed sequence is {current_last_seq}."
                )

        # Step 3: Atomic Compare-and-Swap
        # Update ONLY IF the database document still has last_sequence < sequence
        update_result = await collection.update_one(
            {
                "_id": composite_key,
                "last_sequence": {"$lt": sequence}
            },
            {
                "$set": {
                    "last_sequence": sequence,
                    "last_timestamp": timestamp,
                    "updated_at": now,
                }
            }
        )

        # In MongoDB or our InMemoryCollection, matched_count == 0 means another concurrent worker
        # beat us to advancing the sequence!
        if update_result.matched_count == 0:
            logger.warning(f"[PipelineGuard] Concurrent race detected: atomic CAS failed for sequence={sequence} on {composite_key}")
            raise ReplaySequenceError(
                f"Atomic sequence update failed for sequence {sequence}: concurrent publisher advanced the sequence."
            )

        # Step 4: Sequence Gap Evaluation
        gap = sequence - current_last_seq
        gap_detected = gap > self.max_allowed_gap
        gap_size = gap - 1 if gap_detected else 0
        if gap_detected:
            logger.warning(
                f"[PipelineGuard] Sequence gap detected for {composite_key}: "
                f"jumped from {current_last_seq} to {sequence} (gap={gap-1} batches)."
            )

        return gap_detected, gap_size

    async def verify_request(
        self,
        raw_body: bytes,
        headers: Dict[str, str],
        authenticated_sensor_id: str,
        authenticated_tenant_id: str,
        strict: Optional[bool] = None,
    ) -> PipelineIntegrityVerdict:
        """
        Comprehensive request-level pipeline integrity verification.
        Validates:
        1. Signature header presence and formatting.
        2. Timestamp freshness window (+/- 15s).
        3. Exact-body HMAC-SHA256 signature against derived sensor key.
        4. Atomic database-backed monotonic sequence advancement.
        """
        is_strict = self.strict_mode if strict is None else strict

        def get_header(name: str) -> Optional[str]:
            target = name.lower()
            for k, v in headers.items():
                if k.lower() == target:
                    return str(v)
            return None

        sig_header = get_header("X-Sensor-Signature")
        seq_header = get_header("X-Sensor-Sequence")
        ts_header = get_header("X-Sensor-Timestamp")
        key_ver_header = get_header("X-Sensor-Key-Version") or "v1"

        # Check for missing headers in strict mode vs migration mode
        if not sig_header or not seq_header or not ts_header:
            if is_strict:
                raise MissingIntegrityHeadersError()
            else:
                # Migration mode: accept unverified request with warning
                logger.warning(
                    f"[PipelineGuard] Unauthenticated legacy batch received from {authenticated_sensor_id} "
                    "(Pipeline strict mode disabled)."
                )
                return PipelineIntegrityVerdict(
                    is_valid=True,
                    sensor_id=authenticated_sensor_id,
                    tenant_id=authenticated_tenant_id,
                    sequence_number=0,
                    timestamp=get_utc_now_timestamp(),
                    key_version="legacy",
                    gap_detected=False,
                )

        # Parse and validate sequence integer
        try:
            seq_val = int(seq_header)
        except ValueError:
            raise PipelineIntegrityError("Header X-Sensor-Sequence must be an integer.", PipelineAnomalyType.MISSING_HEADERS)

        # 1. Freshness Check
        ts_val = self.verify_freshness(ts_header)

        # 2. Cryptographic Signature Check
        is_sig_valid = self.verify_signature(
            raw_body=raw_body,
            signature=sig_header,
            sequence=seq_val,
            timestamp_str=str(ts_header),
            tenant_id=authenticated_tenant_id,
            sensor_id=authenticated_sensor_id,
            key_version=key_ver_header,
        )
        if not is_sig_valid:
            logger.critical(
                f"[PipelineGuard] HMAC SIGNATURE VERIFICATION FAILED for sensor {authenticated_sensor_id} "
                f"(tenant {authenticated_tenant_id}, seq {seq_val}, key_ver {key_ver_header})"
            )
            raise InvalidSignatureError()

        # 3. Multi-Worker Atomic Monotonic Sequence & Replay Defense
        gap_detected, gap_size = await self.verify_and_advance_sequence_atomic(
            tenant_id=authenticated_tenant_id,
            sensor_id=authenticated_sensor_id,
            sequence=seq_val,
            timestamp=ts_val,
        )

        return PipelineIntegrityVerdict(
            is_valid=True,
            sensor_id=authenticated_sensor_id,
            tenant_id=authenticated_tenant_id,
            sequence_number=seq_val,
            timestamp=ts_val,
            key_version=key_ver_header,
            gap_detected=gap_detected,
            gap_size=gap_size,
        )


# Global singleton instance
pipeline_guard = PipelineIntegrityGuard()
