"""
backend/self_defense/response_policies.py

Response policies, action permissions, and thresholds for the
Autonomous Response Controller (ARC) (Stage 2 Step 6).
"""

import os
from enum import Enum
from typing import Dict, Any, Optional, List


# Configurable thresholds
TRUST_COLLAPSE_THRESHOLD = float(os.getenv("NETRIQ_TRUST_COLLAPSE_THRESHOLD", "0.50"))
TRUST_WARNING_THRESHOLD = float(os.getenv("NETRIQ_TRUST_WARNING_THRESHOLD", "0.80"))


class ContainmentMode(str, Enum):
    """Execution policy for sensor containment."""
    IMMEDIATE_FULL = "IMMEDIATE_FULL"               # Option A: Immediately revoke and quarantine
    STAGED_AUTONOMOUS = "STAGED_AUTONOMOUS"         # Option B: Quarantine first, then revoke upon check confirmation
    HUMAN_APPROVED = "HUMAN_APPROVED"               # Option C: Alert only, wait for manual admin approval


DEFAULT_CONTAINMENT_MODE = ContainmentMode(
    os.getenv("NETRIQ_CONTAINMENT_MODE", ContainmentMode.STAGED_AUTONOMOUS.value)
)


class ResponseTriggerType(str, Enum):
    TRUST_COLLAPSE = "TRUST_COLLAPSE"
    INTELLIGENCE_TAMPERING = "INTELLIGENCE_TAMPERING"
    PIPELINE_TAMPERING = "PIPELINE_TAMPERING"
    CANARY_PROBE = "CANARY_PROBE"
    ADMIN_ANOMALY = "ADMIN_ANOMALY"
    MANUAL_ADMIN = "MANUAL_ADMIN"


class ResponseActionType(str, Enum):
    QUARANTINE_TELEMETRY = "QUARANTINE_TELEMETRY"
    REVOKE_CREDENTIALS = "REVOKE_CREDENTIALS"
    DISCONNECT_SENSOR = "DISCONNECT_SENSOR"
    ACTIVATE_SAFE_MODE = "ACTIVATE_SAFE_MODE"
    DEACTIVATE_SAFE_MODE = "DEACTIVATE_SAFE_MODE"
    SUSPEND_AUTOMATED_BLOCKS = "SUSPEND_AUTOMATED_BLOCKS"
    RESUME_AUTOMATED_BLOCKS = "RESUME_AUTOMATED_BLOCKS"
    RESTORE_SENSOR = "RESTORE_SENSOR"


class ResponsePolicyEngine:
    """
    Evaluates incoming security events and determines authorized automated actions.
    Guarantees:
    - Bounded autonomous actions.
    - Tenant-scoped mitigation.
    - Strict recovery rules (cannot auto-restore without authorization).
    """

    def __init__(self, mode: ContainmentMode = DEFAULT_CONTAINMENT_MODE):
        self.mode = mode

    def should_contain_sensor(self, trust_score: float) -> bool:
        """Determines if a sensor's trust score has collapsed below the threshold."""
        return trust_score < TRUST_COLLAPSE_THRESHOLD

    def get_staged_actions(self, trigger: ResponseTriggerType) -> List[ResponseActionType]:
        """Returns the ordered response sequence for a given trigger under current policy."""
        if trigger == ResponseTriggerType.TRUST_COLLAPSE:
            if self.mode == ContainmentMode.STAGED_AUTONOMOUS:
                return [
                    ResponseActionType.QUARANTINE_TELEMETRY,
                    ResponseActionType.REVOKE_CREDENTIALS,
                    ResponseActionType.DISCONNECT_SENSOR,
                ]
            elif self.mode == ContainmentMode.IMMEDIATE_FULL:
                return [
                    ResponseActionType.REVOKE_CREDENTIALS,
                    ResponseActionType.DISCONNECT_SENSOR,
                    ResponseActionType.QUARANTINE_TELEMETRY,
                ]
            else:
                return []

        elif trigger == ResponseTriggerType.INTELLIGENCE_TAMPERING:
            return [
                ResponseActionType.ACTIVATE_SAFE_MODE,
                ResponseActionType.SUSPEND_AUTOMATED_BLOCKS,
            ]

        elif trigger == ResponseTriggerType.PIPELINE_TAMPERING:
            return [
                ResponseActionType.QUARANTINE_TELEMETRY,
            ]

        return []

