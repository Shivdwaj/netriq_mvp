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
    AssetIntegrityType,
    IntelligenceAnomalyType,
    AssetManifestEntry,
    IntelligenceManifest,
    IntelligenceIntegrityVerdict,
    CanaryTokenType,
    CanaryTriggerEvent,
    AdminAnomalyType,
    DualApprovalRecord,
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
from backend.self_defense.intelligence_guard import (
    IntelligenceIntegrityGuard,
    intelligence_guard,
    IntelligenceIntegrityError,
    ManifestSignatureVerificationError,
    AssetIntegrityError,
    ThresholdTamperingError,
    RuleTamperingError,
    SafeModeActiveError,
    generate_release_keypair,
    sign_manifest_payload,
    verify_manifest_signature,
    hash_file_sha256,
)
from backend.self_defense.management_monitor import (
    ManagementSecurityMonitor,
    management_monitor,
    ManagementSecurityError,
    AdminAnomalyError,
    DualApprovalRequiredError,
    FailClosedAuditError,
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
    "AssetIntegrityType",
    "IntelligenceAnomalyType",
    "AssetManifestEntry",
    "IntelligenceManifest",
    "IntelligenceIntegrityVerdict",
    "CanaryTokenType",
    "CanaryTriggerEvent",
    "AdminAnomalyType",
    "DualApprovalRecord",
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
    "IntelligenceIntegrityGuard",
    "intelligence_guard",
    "IntelligenceIntegrityError",
    "ManifestSignatureVerificationError",
    "AssetIntegrityError",
    "ThresholdTamperingError",
    "RuleTamperingError",
    "SafeModeActiveError",
    "generate_release_keypair",
    "sign_manifest_payload",
    "verify_manifest_signature",
    "hash_file_sha256",
    "ManagementSecurityMonitor",
    "management_monitor",
    "ManagementSecurityError",
    "AdminAnomalyError",
    "DualApprovalRequiredError",
    "FailClosedAuditError",
]

