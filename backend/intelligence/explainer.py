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
