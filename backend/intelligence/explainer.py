"""
backend/intelligence/explainer.py
Stage 6: Incident Explanation & Transparent Forensic Reasoning

Explains the evidence, causal relationships, and risk factors:
- What happened: Synthesizes a human-readable executive narrative.
- Why connected: Explains the exact causal chain and temporal relationships.
- Why rated: Transparently displays active risk signals, weights, and anti-double-counting discounts.
- Guided Playbook: Provides context-aware SOC remediation and containment steps.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from backend.intelligence.enricher import EnrichedEventContext
from backend.intelligence.correlator import CorrelatedIncidentState
from backend.intelligence.risk_engine import RiskAssessmentResult
from backend.pipeline.schemas import NormalizedSecurityEvent


class IncidentExplanation(BaseModel):
    """Structured explanation artifact produced by Stage 6."""
    title: str
    incident_type: str
    executive_summary: str
    why_connected: str
    risk_reasoning: str
    recommended_playbook: List[str] = Field(default_factory=list)
    mitre_attack_stages: List[str] = Field(default_factory=list)


class IncidentExplainer:
    """
    Executes Stage 6 of the Intelligence Pipeline:
    Translates mathematical risk metrics and telemetry graphs into plain-English,
    forensically sound, and auditor-ready incident explanations.
    """

    def explain(
        self,
        context: EnrichedEventContext,
        corr_state: CorrelatedIncidentState,
        risk: RiskAssessmentResult
    ) -> IncidentExplanation:
        """Generates comprehensive incident explanation."""
        host = context.subject_hostname or context.subject_ip
        ip = context.subject_ip
        user = context.subject_user
        target_ip = context.target_ip or "internal network"

        # 1. Determine Incident Type
        if len(corr_state.attack_chain) >= 2:
            stages_clean = [s.split(' - ')[0] for s in corr_state.attack_chain]
            incident_type = f"Correlated Attack Chain: {' -> '.join(stages_clean)}"
        elif corr_state.has_crown_jewel:
            incident_type = "Crown Jewel Access Attempt"
        elif corr_state.has_lateral:
            incident_type = "Lateral Movement Activity"
        elif corr_state.has_c2:
            incident_type = "Suspected C2 Communication"
        elif corr_state.has_malicious_proc:
            incident_type = "Malicious Process Execution"
        elif corr_state.is_port_scan or corr_state.observation_count >= 3:
            incident_type = "Possible reconnaissance"
        else:
            incident_type = "Suspicious Network Activity"

        title = f"{incident_type} ({risk.severity_label})"

        # 2. Executive Summary
        if len(corr_state.attack_chain) >= 2:
            stages_summary = " -> ".join(corr_state.attack_chain)
            summary = (
                f"Multi-stage attack chain detected from {ip} ({host}) targeting {target_ip}. "
                f"Progression: {stages_summary}."
            )
        elif corr_state.is_port_scan and corr_state.has_crown_jewel:
            summary = (
                f"Host {ip} ({host}) initiated a multi-port reconnaissance probe across "
                f"{corr_state.unique_ports_count} ports, followed by targeted access attempts "
                f"against high-value internal Crown Jewel assets ({target_ip}). "
                f"The activity represents a critical security risk to enterprise core data."
            )
        elif corr_state.is_port_scan:
            summary = (
                f"Host {ip} ({host}) executed an active network discovery sweep probing "
                f"{corr_state.unique_ports_count} ports across {corr_state.unique_ips_count} destination endpoints. "
                f"Observed telemetry indicates sequential port mapping prior to service exploitation."
            )
        elif corr_state.has_crown_jewel:
            summary = (
                f"Host {ip} ({host}) generated unauthorized connection attempts against "
                f"designated high-value enterprise asset {target_ip} ({context.target_service or 'database'})."
            )
        else:
            summary = (
                f"Anomalous activity detected from {ip} ({host}) targeting {target_ip} "
                f"with {corr_state.observation_count} correlated security events."
            )

        # 3. Why Connected (Causal Correlation Logic)
        why_connected = (
            f"NetrIQ correlated {corr_state.observation_count} distinct observations under tracker key '{corr_state.tracker_key}' "
            f"because they originated from the same authenticated device context within a rolling sliding window. "
            f"Observations exhibit causal progression matching {len(corr_state.attack_chain)} MITRE ATT&CK stages: "
            f"{', '.join(corr_state.stages_detected or ['reconnaissance'])}."
        )

        # 4. Risk Reasoning (Anti-Double-Counting Breakdown)
        active_names = [f"'{s.name}' (weight: {s.effective_weight})" for s in risk.active_signals]
        risk_reasoning = (
            f"Severity rated {risk.severity_label} ({risk.severity_score}/100) based on active signals: "
            f"{'; '.join(active_names)}. "
            f"Anti-double-counting algorithm applied a dampening discount of {risk.dampening_discount_applied} points "
            f"to prevent signal inflation between overlapping frequency bursts and signatures. "
            f"Confidence rated {risk.confidence_label} ({risk.confidence_score}) based on evidence volume and detection reliability."
        )

        # 5. Recommended Playbook
        playbook = [
            f"1. Isolate {host} ({ip}) immediately using NetrIQ 1-Click Endpoint Quarantine to block lateral spread.",
            f"2. Audit active processes and socket connections on {host} ({ip}); inspect parent-child execution trees.",
            f"3. Verify directory authentication logs for user '{user}' across internal authentication infrastructure.",
            f"4. Block targeted destination ports on perimeter firewall egress rules."
        ]

        if corr_state.has_crown_jewel:
            playbook.insert(2, f"Targeted high-value internal asset ({target_ip}): Check database access audit logs for unauthorized queries.")

        return IncidentExplanation(
            title=title,
            incident_type=incident_type,
            executive_summary=summary,
            why_connected=why_connected,
            risk_reasoning=risk_reasoning,
            recommended_playbook=playbook,
            mitre_attack_stages=corr_state.attack_chain
        )

    def explain_event(self, event: NormalizedSecurityEvent) -> Dict[str, Any]:
        """
        Produces a localized forensic feature contribution explanation for an individual
        security event without external ML framework dependencies.
        """
        evidence = event.evidence or {}
        contributions: Dict[str, float] = {}
        risk_factors: List[str] = []

        # 1. Port Sensitivity Contribution
        sensitive_ports = {445: 0.95, 3389: 0.90, 22: 0.85, 1433: 0.90, 80: 0.40, 443: 0.40, 53: 0.50}
        port_weight = sensitive_ports.get(event.destination_port, 0.2)
        contributions["destination_port_sensitivity"] = round(port_weight, 2)
        if event.destination_port in (445, 3389, 22, 1433):
            risk_factors.append(f"Targeting critical administration/database port ({event.destination_port})")

        # 2. Reconnaissance / Scanning Signals
        is_scan = bool(evidence.get("scan_indicator") or evidence.get("conn_state") in ("S0", "SH", "REJ"))
        contributions["reconnaissance_pattern"] = 0.9 if is_scan else 0.0
        if is_scan:
            risk_factors.append(f"Connection state '{evidence.get('conn_state')}' indicates unanswered SYN sweep / port probe")

        # 3. Known Signature / Rule Match
        has_sig = bool(event.rule_id or evidence.get("signature"))
        contributions["signature_match"] = 0.85 if has_sig else 0.0
        if has_sig:
            sig_name = evidence.get("signature") or event.rule_id
            risk_factors.append(f"Matched threat detection signature: {sig_name}")

        # 4. Severity Weight
        sev_map = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2, "INFO": 0.1}
        sev_score = sev_map.get(str(event.severity).upper(), 0.1)
        contributions["severity_baseline"] = sev_score

        # 5. Network Directionality
        direction_map = {"OUTBOUND": 0.7, "INBOUND": 0.6, "INTERNAL": 0.5, "UNKNOWN": 0.3}
        dir_score = direction_map.get(str(event.direction).upper(), 0.4)
        contributions["network_direction"] = dir_score

        # 6. TLS Metadata Analysis
        tls_info = evidence.get("tls")
        if tls_info and isinstance(tls_info, dict):
            sni = tls_info.get("sni")
            ja3 = tls_info.get("ja3")
            contributions["tls_metadata_presence"] = 0.6
            if sni:
                risk_factors.append(f"TLS Client Hello SNI target: {sni}")
            if ja3:
                risk_factors.append(f"TLS JA3 client fingerprint: {ja3}")
        else:
            contributions["tls_metadata_presence"] = 0.0

        # Primary Driver Determination
        if has_sig:
            primary_driver = "Signature Detection Rule"
        elif is_scan:
            primary_driver = "Network Reconnaissance / Port Scan"
        elif event.destination_port in sensitive_ports:
            primary_driver = "Sensitive Port Access Attempt"
        else:
            primary_driver = f"Anomalous {event.protocol} Traffic"

        # Forensic Summary Synthesis
        summary = (
            f"Event {event.event_id or 'unknown'} ({event.detection_source}) from "
            f"{event.source_ip}:{event.source_port} to {event.destination_ip}:{event.destination_port} "
            f"flagged as {event.severity} severity. Primary driver: {primary_driver}."
        )

        return {
            "event_id": event.event_id,
            "detection_source": event.detection_source,
            "severity": event.severity,
            "primary_driver": primary_driver,
            "forensic_summary": summary,
            "risk_factors": risk_factors,
            "feature_contributions": contributions,
            "mitre_technique": evidence.get("mitre") or ("T1046 Network Service Discovery" if is_scan else None),
            "evidence": {
                k: v for k, v in evidence.items() if k not in ("payload", "raw_packet")
            }
        }


incident_explainer = IncidentExplainer()
