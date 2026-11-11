"""
backend/self_defense

NetrIQ Stage 2: Autonomous Self-Defense Architecture
- Sensor Trust Engine (STE)
- Pipeline Integrity Guard (PIG)
- Intelligence Integrity Guard (IIG)
- Management Security Monitor (MSM)
- Autonomous Response Controller (ARC)
- Cryptographically Sealed Audit Ledger (CAL)
- Independent Security Watchdog
"""

from backend.self_defense.schemas import (
    AuditRecord,
    AuditAnchor,
    AuditVerificationResult,
    SecurityAlert,
    TamperType,
    TrustTier,
    SensorAnomalyType,
    SensorAnomalyEvent,
    SensorTrustScore,
    PipelineAnomalyType,
    PipelineIntegrityVerdict,
)
from backend.self_defense.audit_ledger import (
    CryptographicallySealedAuditLedger,
    AuditStorageError,
    AuditTamperError,
)
from backend.self_defense.watchdog import (
    IndependentSecurityWatchdog,
    AlertSink,
    FileAlertSink,
    MemoryAlertSink,
)
from backend.self_defense.sensor_trust import (
    SensorTrustEngine,
    sensor_trust_engine,
)
from backend.self_defense.pipeline_guard import (
    PipelineIntegrityGuard,
    pipeline_guard,
    PipelineIntegrityError,
    MissingIntegrityHeadersError,
    InvalidSignatureError,
    ExpiredTimestampError,
    FutureTimestampError,
    ReplaySequenceError,
    derive_sensor_signing_key,
)

__all__ = [
    "AuditRecord",
    "AuditAnchor",
    "AuditVerificationResult",
    "SecurityAlert",
    "TamperType",
    "TrustTier",
    "SensorAnomalyType",
    "SensorAnomalyEvent",
    "SensorTrustScore",
    "PipelineAnomalyType",
    "PipelineIntegrityVerdict",
    "CryptographicallySealedAuditLedger",
    "AuditStorageError",
    "AuditTamperError",
    "IndependentSecurityWatchdog",
    "AlertSink",
    "FileAlertSink",
    "MemoryAlertSink",
    "SensorTrustEngine",
    "sensor_trust_engine",
    "PipelineIntegrityGuard",
    "pipeline_guard",
    "PipelineIntegrityError",
    "MissingIntegrityHeadersError",
    "InvalidSignatureError",
    "ExpiredTimestampError",
    "FutureTimestampError",
    "ReplaySequenceError",
    "derive_sensor_signing_key",
]

