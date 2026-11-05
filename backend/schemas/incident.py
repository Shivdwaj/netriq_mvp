import uuid
from enum import Enum
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

from backend.pipeline.schemas import get_utc_iso_now

class IncidentStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"

class AuditEntry(BaseModel):
    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=get_utc_iso_now)
    user: str
    action: str # STATUS_CHANGE, ASSIGNMENT, NOTE_ADDED, SEVERITY_CHANGE, EVIDENCE_ATTACHED, CLOSURE
    details: Dict[str, Any] = Field(default_factory=dict)
    reason: Optional[str] = None

class InvestigationNote(BaseModel):
    note_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=get_utc_iso_now)
    author: str
    content: str

class IncidentItem(BaseModel):
    id: str
    tenant_id: str = "default"
    incident_code: Optional[str] = None
    status: str = IncidentStatus.NEW.value
    severity: str
    title: Optional[str] = None
    description: str
    incident_type: Optional[str] = None
    confidence: Optional[float] = None
    confidence_label: Optional[str] = None
    assigned_to: Optional[str] = None
    created_at: float
    updated_at: Optional[float] = None
    closed_at: Optional[float] = None
    closed_by: Optional[str] = None
    resolution_notes: Optional[str] = None
    affected_assets: Optional[List[str]] = None
    response_action: Optional[str] = None
    response_success: Optional[bool] = None
    notes: Optional[str] = None # Legacy single-string note support
    investigation_notes: List[InvestigationNote] = Field(default_factory=list)
    audit_history: List[AuditEntry] = Field(default_factory=list)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_transferred: Optional[int] = None
    packets_transferred: Optional[int] = None
    source_label: Optional[str] = None
    target_label: Optional[str] = None
    hostname: Optional[str] = None
    mac: Optional[str] = None
    user: Optional[str] = None
    attack_chain: Optional[List[str]] = None
    evidence: Optional[List[Dict[str, Any]]] = None
    recommended_investigation_steps: Optional[List[str]] = None

class IncidentUpdateReq(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None
    severity: Optional[str] = None
    assigned_to: Optional[str] = None
    reason: Optional[str] = None

class IncidentStatusUpdateReq(BaseModel):
    status: str
    reason: str
    resolution_notes: Optional[str] = None

class IncidentAssignmentReq(BaseModel):
    assigned_to: str
    reason: Optional[str] = None

class IncidentNoteReq(BaseModel):
    content: str

class IncidentSeverityUpdateReq(BaseModel):
    severity: str
    reason: str

class IncidentEvidenceAttachReq(BaseModel):
    evidence: Dict[str, Any]
    reason: Optional[str] = None
