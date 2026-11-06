"""
backend/intelligence/enricher.py
Stage 1: Event Interpretation
Stage 2: Context Enrichment & Capability 3: Threat Context Enrichment

Enriches normalized events with:
- Semantic intent and entity resolution (Subject host/user -> Target service/asset).
- Asset criticality & Crown Jewel topology resolution.
- Threat Intelligence reputation lookups against trusted indicators (IoCs).
- Protocol semantics validation (e.g. non-standard port usage).
"""

import time
import ipaddress
from typing import Dict, Any, List, Optional, Set
from pydantic import BaseModel, Field

from backend.pipeline.schemas import NormalizedSecurityEvent
from backend.intelligence.config import IntelligenceConfig, intelligence_config
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class ThreatIntelMatch(BaseModel):
    """Result of matching an IP, domain, or hash against Threat Intelligence."""
    indicator: str
    indicator_type: str  # ipv4, domain, hash, cidr
    threat_actor: Optional[str] = None
    threat_type: str  # c2_server, scanner, tor_exit, malware_source
    confidence: float = 0.85
    tags: List[str] = Field(default_factory=list)
    description: str = ""


class ThreatIntelStore:
    """
    In-memory Threat Intelligence repository supporting dynamic additions,
    exact matches, and CIDR subnet sweeps with zero hardcoded values.
    """

    def __init__(self):
        self._indicators: Dict[str, ThreatIntelMatch] = {}
        self._cidr_ranges: List[tuple] = []  # (IPv4Network, ThreatIntelMatch)

    def add_indicator(
        self,
        indicator: str,
        threat_type: str,
        indicator_type: str = "ipv4",
        confidence: float = 0.90,
        threat_actor: Optional[str] = None,
        tags: Optional[List[str]] = None,
        description: str = ""
    ):
        """Registers a trusted threat intelligence indicator."""
        match_record = ThreatIntelMatch(
            indicator=indicator,
            indicator_type=indicator_type,
            threat_actor=threat_actor,
            threat_type=threat_type,
            confidence=confidence,
            tags=tags or [],
            description=description
        )

        if "/" in indicator and indicator_type in ("ipv4", "cidr"):
            try:
                network = ipaddress.ip_network(indicator, strict=False)
                self._cidr_ranges.append((network, match_record))
            except Exception:
                pass
        else:
            self._indicators[indicator.lower().strip()] = match_record

    def lookup(self, target: str) -> Optional[ThreatIntelMatch]:
        """Performs fast hash lookup and fallback CIDR evaluation for an IP/domain."""
        clean = (target or "").lower().strip()
        if clean in self._indicators:
            return self._indicators[clean]

        # Check CIDR networks if target is an IP address
        try:
            ip_obj = ipaddress.ip_address(clean)
            for network, record in self._cidr_ranges:
                if ip_obj in network:
                    return record
        except Exception:
            pass

        return None


# Global Threat Intelligence Feed instance
threat_intel_feed = ThreatIntelStore()


class EnrichedEventContext(BaseModel):
    """
    Structured outcome of Stage 1 (Interpretation) and Stage 2 (Enrichment).
    """
    event_id: str
    timestamp: float
    tenant_id: str

    # Stage 1: Interpretation
    subject_ip: str
    subject_hostname: str
    subject_user: str
    target_ip: Optional[str] = None
    target_port: int = 0
    target_service: Optional[str] = None
    protocol: str = "TCP"
    direction: str = "internal"  # internal, outbound, inbound
    semantic_action: str = "network_connection"
    mitre_stage: str = "reconnaissance"
    mitre_technique: str = "T1046 Network Service Discovery"

    # Stage 2: Context Enrichment
    is_crown_jewel: bool = False
    is_lateral_target: bool = False
    is_elevated_subject: bool = False
    is_suspicious_tool: bool = False
    threat_intel: Optional[ThreatIntelMatch] = None
    asset_criticality_multiplier: float = 1.0
    summary: str = ""


class ContextEnricher:
    """
    Executes Stage 1 & 2 of the Intelligence Pipeline:
    - Interprets raw fields into subject/target semantic intent.
    - Enriches with asset criticality, topology context, and threat intelligence.
    """

    def __init__(self, config: Optional[IntelligenceConfig] = None, ti_feed: Optional[ThreatIntelStore] = None):
        self.config = config or intelligence_config
        self.ti_feed = ti_feed or threat_intel_feed

    def enrich(self, event: NormalizedSecurityEvent, custom_crown_jewels: Optional[Set[str]] = None) -> EnrichedEventContext:
        """Transforms a NormalizedSecurityEvent into an enriched semantic context."""
        now = time.time()
        tenant_id = event.tenant_id or "default"

        # 1. Subject Resolution (Who acted)
        device = event.device
        subject_ip = (device.ip if device else None) or event.source_ip or "0.0.0.0"
        subject_hostname = (device.hostname if device else None) or "Unknown Host"
        subject_user = (device.logged_in_user if device else None) or "Unknown User"
        is_elevated = subject_user.lower() in ("root", "administrator", "system")

        # 2. Target Resolution (Who was targeted)
        target_ip = event.destination_ip or ""
        target_port = int(event.destination_port or 0)
        protocol = (event.protocol or "TCP").upper()
        direction = getattr(event.network, "direction", None) or getattr(event, "direction", "internal")

        # 3. Protocol & Topology Service Mapping
        lateral_ports = self.config.lateral_ports
        crown_jewel_ports = self.config.crown_jewel_ports
        critical_tools = self.config.critical_tools

        is_crown_jewel = False
        is_lateral_target = False
        target_service = None
        mitre_stage = "reconnaissance"
        mitre_technique = "T1046 Network Service Discovery"
        semantic_action = "network_probe"

        # Check explicit Crown Jewel IPs or known ports
        if custom_crown_jewels and (target_ip in custom_crown_jewels or subject_ip in custom_crown_jewels):
            is_crown_jewel = True
            target_service = "High-Value Enterprise Asset"
            mitre_stage = "crown_jewel_access"
            mitre_technique = "T1530 Data from Internal/Cloud Storage"
            semantic_action = "crown_jewel_access"

        elif target_port in crown_jewel_ports and direction == "internal":
            is_crown_jewel = True
            target_service = crown_jewel_ports[target_port]
            mitre_stage = "crown_jewel_access"
            mitre_technique = "T1530 Data from Internal/Cloud Storage"
            semantic_action = "crown_jewel_access"

        elif target_port in lateral_ports and direction == "internal":
            is_lateral_target = True
            target_service = lateral_ports[target_port]
            mitre_stage = "lateral_movement"
            mitre_technique = "T1021 Remote Services"
            semantic_action = "lateral_movement_probe"

        elif direction == "outbound" and target_port not in (80, 443, 53, 123):
            target_service = f"External Port {target_port}"
            mitre_stage = "c2_exfil"
            mitre_technique = "T1071 Application Layer Protocol"
            semantic_action = "outbound_anomaly"

        # Check endpoint binary execution if present
        is_suspicious_tool = False
        if event.endpoint:
            proc_name = (event.endpoint.process_name or "").lower()
            if proc_name in critical_tools or event.endpoint.is_suspicious:
                is_suspicious_tool = True
                mitre_stage = "malicious_process"
                mitre_technique = critical_tools.get(proc_name, "T1059 Command and Scripting Interpreter")
                semantic_action = "offensive_binary_execution"
                target_service = f"Process: {proc_name}"

        # 4. Threat Intelligence Lookup (Capability 3)
        ti_match = self.ti_feed.lookup(target_ip) or self.ti_feed.lookup(subject_ip)
        if ti_match and mitre_stage == "reconnaissance":
            mitre_stage = "c2_exfil"
            mitre_technique = "T1071 Command and Control"
            semantic_action = f"threat_intel_match_{ti_match.threat_type}"

        # 5. Asset Criticality Multiplier
        crit_multiplier = 1.0
        if is_crown_jewel:
            crit_multiplier = 1.5
        elif is_lateral_target:
            crit_multiplier = 1.25
        elif is_elevated:
            crit_multiplier = 1.15

        summary = f"{semantic_action.replace('_', ' ').capitalize()} from {subject_ip} ({subject_hostname}) to {target_ip}:{target_port}"
        if target_service:
            summary += f" [{target_service}]"

        return EnrichedEventContext(
            event_id=event.event_id,
            timestamp=now,
            tenant_id=tenant_id,
            subject_ip=subject_ip,
            subject_hostname=subject_hostname,
            subject_user=subject_user,
            target_ip=target_ip,
            target_port=target_port,
            target_service=target_service,
            protocol=protocol,
            direction=direction,
            semantic_action=semantic_action,
            mitre_stage=mitre_stage,
            mitre_technique=mitre_technique,
            is_crown_jewel=is_crown_jewel,
            is_lateral_target=is_lateral_target,
            is_elevated_subject=is_elevated,
            is_suspicious_tool=is_suspicious_tool,
            threat_intel=ti_match,
            asset_criticality_multiplier=crit_multiplier,
            summary=summary
        )
