from backend.database.database import DatabaseManager
from backend.database.collections import (
    BaseRepository,
    ThreatRepository,
    organizations_repo,
    organisations_repo,
    users_repo,
    roles_repo,
    sensors_repo,
    sensor_health_repo,
    network_events_repo,
    events_repo,
    detection_rules_repo,
    rules_repo,
    alerts_repo,
    threats_repo,
    incidents_repo,
    incident_events_repo,
    evidence_repo,
    audit_logs_repo,
    responses_repo,
    feedback_repo,
    reports_repo,
    settings_repo,
    predictions_repo,
    idempotency_repo
)
from backend.database.indexes import ensure_indexes
from backend.database.backup import run_backup
from backend.database.restore import run_restore
from backend.database.exceptions import (
    DatabaseConnectionError,
    DocumentNotFoundError,
    DuplicateKeyError,
    FatalRestoreError
)

__all__ = [
    "DatabaseManager",
    "BaseRepository",
    "ThreatRepository",
    "organizations_repo",
    "organisations_repo",
    "users_repo",
    "roles_repo",
    "sensors_repo",
    "sensor_health_repo",
    "network_events_repo",
    "events_repo",
    "detection_rules_repo",
    "rules_repo",
    "alerts_repo",
    "threats_repo",
    "incidents_repo",
    "incident_events_repo",
    "evidence_repo",
    "audit_logs_repo",
    "responses_repo",
    "feedback_repo",
    "reports_repo",
    "settings_repo",
    "predictions_repo",
    "idempotency_repo",
    "ensure_indexes",
    "run_backup",
    "run_restore",
    "DatabaseConnectionError",
    "DocumentNotFoundError",
    "DuplicateKeyError",
    "FatalRestoreError"
]
