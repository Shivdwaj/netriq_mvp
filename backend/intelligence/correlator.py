"""
backend/intelligence/correlator.py
Stage 4: Causal Correlation & Capability 1: Rule-Based Correlation

Connects events that share meaningful relationships across sliding time windows:
- Groups observations by entity (device / IP / user).
- Synthesizes multi-stage MITRE ATT&CK progression chains.
- Identifies reconnaissance, lateral movement, crown jewel access, and C2 stages.
- No hardcoded constants: window intervals and thresholds are dynamically configured.
"""

import time
import collections
from typing import Dict, List, Any, Optional, Set
from pydantic import BaseModel, Field

from backend.pipeline.schemas import NormalizedSecurityEvent
from backend.intelligence.config import IntelligenceConfig, intelligence_config
from backend.intelligence.enricher import EnrichedEventContext
from backend.intelligence.behaviour import BehaviourAssessment
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class DeviceActivityTracker:
    """
    Maintains a device's attack timeline and sliding window observations.
    """

    def __init__(self, key: str, window_seconds: float = 600.0):
        self.key = key
        self.window_seconds = window_seconds
        self.events: collections.deque = collections.deque()
        self.scanned_ports: Set[int] = set()
        self.scanned_ips: Set[str] = set()
        self.lateral_attempts: List[Dict[str, Any]] = []
        self.crown_jewel_attempts: List[Dict[str, Any]] = []
        self.c2_attempts: List[Dict[str, Any]] = []
        self.suspicious_processes: List[Dict[str, Any]] = []
        self.active_incident_id: Optional[str] = None
        self.last_updated: float = time.time()

    def prune(self, now: float):
        """Discards events that fell outside the sliding time window."""
        cutoff = now - self.window_seconds
        while self.events and self.events[0].get("timestamp", 0) < cutoff:
            self.events.popleft()

        # Recalculate active working sets
        self.scanned_ports = {e["dst_port"] for e in self.events if e.get("dst_port")}
        self.scanned_ips = {e["dst_ip"] for e in self.events if e.get("dst_ip")}
        self.lateral_attempts = [e for e in self.events if e.get("stage") == "lateral_movement"]
        self.crown_jewel_attempts = [e for e in self.events if e.get("stage") == "crown_jewel_access"]
        self.c2_attempts = [e for e in self.events if e.get("stage") == "c2_exfil"]
        self.suspicious_processes = [e for e in self.events if e.get("stage") == "malicious_process"]


class CorrelatedIncidentState(BaseModel):
    """Correlated state resulting from Stage 4 analysis."""
    tracker_key: str
    attack_chain: List[str] = Field(default_factory=list)
    stages_detected: List[str] = Field(default_factory=list)
    is_port_scan: bool = False
    has_lateral: bool = False
    has_crown_jewel: bool = False
    has_c2: bool = False
    has_malicious_proc: bool = False
    unique_ports_count: int = 0
    unique_ips_count: int = 0
    observation_count: int = 0
    should_synthesize_incident: bool = False


class RuleBasedCorrelator:
    """
    Executes Stage 4: Connects events based on known relationships, temporal proximity,
    and attack progression.
    """

    def __init__(self, config: Optional[IntelligenceConfig] = None):
        self.config = config or intelligence_config
        self._trackers: Dict[str, DeviceActivityTracker] = {}

    def get_tracker(self, key: str) -> DeviceActivityTracker:
        now = time.time()
        if key not in self._trackers:
            self._trackers[key] = DeviceActivityTracker(key, self.config.window_seconds)
        tracker = self._trackers[key]
        tracker.prune(now)
        tracker.last_updated = now
        return tracker

    def record_observation(
        self,
        tracker: DeviceActivityTracker,
        context: EnrichedEventContext,
        behaviour: BehaviourAssessment,
        evidence_dict: Optional[Dict[str, Any]] = None
    ) -> CorrelatedIncidentState:
        """Appends enriched event and evaluates multi-stage correlation state."""
        now = time.time()

        item = {
            "event_id": context.event_id,
            "timestamp": now,
            "stage": context.mitre_stage,
            "mitre": context.mitre_technique,
            "src_ip": context.subject_ip,
            "dst_ip": context.target_ip,
            "dst_port": context.target_port,
            "protocol": context.protocol,
            "summary": context.summary,
            "details": evidence_dict or {}
        }
        if context.is_suspicious_tool:
            item["process_name"] = context.target_service

        tracker.events.append(item)
        tracker.prune(now)

        # Evaluate stages
        unique_ports = len(tracker.scanned_ports)
        unique_ips = len(tracker.scanned_ips)
        has_lateral = len(tracker.lateral_attempts) > 0
        has_crown_jewel = len(tracker.crown_jewel_attempts) > 0
        has_c2 = len(tracker.c2_attempts) > 0
        has_malicious_proc = len(tracker.suspicious_processes) > 0

        # Port scan evaluation against configurable thresholds
        is_port_scan = (
            unique_ports >= self.config.port_scan_port_threshold or
            unique_ips >= self.config.port_scan_ip_threshold
        )

        attack_chain: List[str] = []
        stages: List[str] = []

        if is_port_scan:
            stages.append("reconnaissance")
            attack_chain.append(f"Stage 1: Discovery (T1046) - Probed {unique_ports} ports across {unique_ips} hosts")
        if has_malicious_proc:
            stages.append("malicious_process")
            proc_names = list({p.get('process_name') for p in tracker.suspicious_processes if p.get('process_name')})
            attack_chain.append(f"Stage 2: Execution (T1059) - Offensive tooling launched ({', '.join(proc_names)})")
        if has_lateral:
            stages.append("lateral_movement")
            attack_chain.append(f"Stage 3: Lateral Movement (T1021) - {len(tracker.lateral_attempts)} sensitive service probes")
        if has_crown_jewel:
            stages.append("crown_jewel_access")
            attack_chain.append(f"Stage 4: Collection (T1530) - Targeted high-value internal database/auth assets")
        if has_c2:
            stages.append("c2_exfil")
            attack_chain.append(f"Stage 5: Command & Control (T1071) - Anomalous outbound communication established")

        obs_count = len(tracker.events)
        # Minimum criteria: 2+ stages OR critical binary execution OR port scan OR configured observation threshold
        should_trigger = (
            len(attack_chain) >= 2 or
            has_malicious_proc or
            is_port_scan or
            obs_count >= self.config.min_observations_for_incident
        )

        return CorrelatedIncidentState(
            tracker_key=tracker.key,
            attack_chain=attack_chain,
            stages_detected=stages,
            is_port_scan=is_port_scan,
            has_lateral=has_lateral,
            has_crown_jewel=has_crown_jewel,
            has_c2=has_c2,
            has_malicious_proc=has_malicious_proc,
            unique_ports_count=unique_ports,
            unique_ips_count=unique_ips,
            observation_count=obs_count,
            should_synthesize_incident=should_trigger
        )
