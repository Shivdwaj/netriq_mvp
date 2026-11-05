import uuid
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from backend.pipeline.schemas import get_utc_iso_now

class DetectionEngineType(str, Enum):
    SIGNATURE = "signature"
    RULE = "rule"
    BEHAVIOUR = "behaviour"

class DetectionFinding(BaseModel):
    """
    NetrIQ Layer 3 Detection Finding.
    Standardized alert/finding emitted by the Signature, Rule, or Behaviour Analysis Engine.
    """
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    engine_type: DetectionEngineType
    rule_id: str                          # e.g., "SURICATA:2010935", "NETRIQ:RULE:PORT_SCAN", "NETRIQ:BEHAVIOUR:EGRESS_OUTLIER"
    title: str                            # Human-readable detection name
    description: str                      # Concise technical explanation of finding
    severity: str = "MEDIUM"              # INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence: float = 0.8               # 0.0 to 1.0 confidence score
    mitre_technique: Optional[str] = None # e.g., "T1046 Network Service Discovery"
    mitre_stage: Optional[str] = None     # discovery, initial_access, lateral_movement, c2_exfil, collection
    source_ip: str
    destination_ip: str
    source_port: int = 0
    destination_port: int = 0
    protocol: str = "TCP"
    timestamp: str = Field(default_factory=get_utc_iso_now)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    matched_event_ids: List[str] = Field(default_factory=list)
