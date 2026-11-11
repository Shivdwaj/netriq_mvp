from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, model_validator
from backend.auth.roles import Role

class EventType(str, Enum):
    LIVE_VERDICT = "live_verdict"
    QUARANTINE_ACTION = "quarantine_action"
    MONITOR_STATUS = "monitor_status"
    NEW_INCIDENT = "new_incident"
    BEHAVIOR_ALERT = "behavior_alert"

class Event(BaseModel):
    """Base class for all broadcastable events."""
    event_type: EventType
    target_audience: List[Role]
    payload: Dict[str, Any]
    tenant_id: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def extract_tenant_id(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if not data.get("tenant_id"):
                payload = data.get("payload")
                if isinstance(payload, dict) and payload.get("tenant_id"):
                    data["tenant_id"] = payload["tenant_id"]
        return data

class LiveVerdictEvent(Event):
    event_type: EventType = EventType.LIVE_VERDICT
    # Only analysts and admins should see raw live traffic verdicts
    target_audience: List[Role] = [Role.ANALYST, Role.ADMIN]

class QuarantineActionEvent(Event):
    event_type: EventType = EventType.QUARANTINE_ACTION
    # Everyone can see high-level quarantine actions
    target_audience: List[Role] = [Role.VIEWER, Role.ANALYST, Role.ADMIN]

class MonitorStatusEvent(Event):
    event_type: EventType = EventType.MONITOR_STATUS
    target_audience: List[Role] = [Role.VIEWER, Role.ANALYST, Role.ADMIN]

class NewIncidentEvent(Event):
    event_type: EventType = EventType.NEW_INCIDENT
    target_audience: List[Role] = [Role.VIEWER, Role.ANALYST, Role.ADMIN]

class BehaviorAlertEvent(Event):
    event_type: EventType = EventType.BEHAVIOR_ALERT
    # Broadcast to Analysts and Admins who possess quarantine authority
    target_audience: List[Role] = [Role.ANALYST, Role.ADMIN]
