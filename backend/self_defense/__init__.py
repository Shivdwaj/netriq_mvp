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
    "CryptographicallySealedAuditLedger",
    "AuditStorageError",
    "AuditTamperError",
    "IndependentSecurityWatchdog",
    "AlertSink",
    "FileAlertSink",
    "MemoryAlertSink",
    "SensorTrustEngine",
    "sensor_trust_engine",
]

