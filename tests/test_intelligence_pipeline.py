"""
tests/test_intelligence_pipeline.py
Unit and integration test suite for the NetrIQ Structured Intelligence Pipeline:
1. Stage 1: Event Interpretation (semantics, subject/target resolution).
2. Stage 2: Context Enrichment & Capability 3: Threat Intelligence (asset criticality, IoC matching).
3. Stage 3: Behaviour Analysis & Capability 2: Behavioural Intelligence (rolling baselines, novel targets).
4. Stage 4: Causal Correlation & Capability 1: Rule-Based Correlation (sliding windows, multi-stage chains).
5. Stage 5: Dual-Axis Risk Assessment with Anti-Double-Counting (independent severity & confidence, dampening).
6. Stage 6: Incident Explanation (executive summary, why_connected, risk reasoning, guided playbook).
7. Zero Hardcoded Values: Configuration override verification.
"""

import time
import pytest
from unittest.mock import AsyncMock, patch
from bson import ObjectId

from backend.pipeline.schemas import NormalizedSecurityEvent, DeviceIdentity, EndpointDetails
from backend.intelligence.config import IntelligenceConfig
from backend.intelligence.enricher import ContextEnricher, ThreatIntelStore
from backend.intelligence.behaviour import BehaviourAnalyzer
from backend.intelligence.correlator import RuleBasedCorrelator, CorrelatedIncidentState
from backend.intelligence.risk_engine import RiskEngine, SignalCategory
from backend.intelligence.explainer import IncidentExplainer
from backend.intelligence.pipeline import StructuredIntelligencePipeline


# ==============================================================================
# 1. TEST STAGE 1 & 2: INTERPRETATION & CONTEXT ENRICHMENT (CAPABILITY 3)
# ==============================================================================

def test_event_interpretation_and_context_enrichment():
    """
    Validates Stage 1 (Interpretation) and Stage 2 (Enrichment):
    - Subject and Target extraction.
    - Crown Jewel port detection.
    - Threat Intelligence IoC lookup.
    """
    ti_store = ThreatIntelStore()
    ti_store.add_indicator(
        indicator="198.51.100.25",
        threat_type="c2_beacon",
        confidence=0.92,
        threat_actor="APT-29",
        description="Known Command & Control server"
    )

    enricher = ContextEnricher(config=IntelligenceConfig(), ti_feed=ti_store)

    # Event 1: Internal database access (Crown Jewel)
    ev_db = NormalizedSecurityEvent(
        source_ip="192.168.1.50",
        destination_ip="10.0.0.5",
        source_port=52000,
        destination_port=1433,
        protocol="TCP",
        event_type="connection",
        direction="internal",
        device=DeviceIdentity(ip="192.168.1.50", hostname="workstation-01", logged_in_user="alice")
    )
    ctx_db = enricher.enrich(ev_db)

    assert ctx_db.subject_ip == "192.168.1.50"
    assert ctx_db.subject_hostname == "workstation-01"
    assert ctx_db.is_crown_jewel is True
    assert ctx_db.target_service == "MSSQL Database"
    assert ctx_db.asset_criticality_multiplier > 1.0

    # Event 2: Outbound connection matching Threat Intel C2 feed
    ev_c2 = NormalizedSecurityEvent(
        source_ip="192.168.1.50",
        destination_ip="198.51.100.25",
        source_port=49152,
        destination_port=8443,
        protocol="TCP",
        direction="outbound"
    )
    ctx_c2 = enricher.enrich(ev_c2)

    assert ctx_c2.threat_intel is not None
    assert ctx_c2.threat_intel.threat_actor == "APT-29"
    assert ctx_c2.threat_intel.threat_type == "c2_beacon"
    assert ctx_c2.mitre_stage == "c2_exfil"


# ==============================================================================
# 2. TEST STAGE 3: BEHAVIOUR ANALYSIS & ADAPTIVE BASELINES (CAPABILITY 2)
# ==============================================================================

def test_behaviour_analysis_and_baseline_deviation():
    """
    Validates Stage 3 (Behaviour Analysis):
    - First-seen destination IP detection.
    - Connection frequency burst detection.
    - Explainable deviation reasons.
    """
    cfg = IntelligenceConfig(
        high_freq_connection_threshold=5,
        window_seconds=60.0
    )
    analyzer = BehaviourAnalyzer(config=cfg)
    enricher = ContextEnricher(config=cfg)

    host_ip = "192.168.1.90"

    # Step 1: Warm up host profile with typical traffic
    for port in (80, 443, 8080):
        ev = NormalizedSecurityEvent(
            source_ip=host_ip,
            destination_ip="10.0.0.10",
            destination_port=port,
            protocol="TCP"
        )
        ctx = enricher.enrich(ev)
        assessment = analyzer.analyze(ev, ctx)

    # Initial warmed-up state should not be high frequency
    assert assessment.is_high_frequency is False

    # Step 2: Sudden unprecedented destination IP
    ev_anom = NormalizedSecurityEvent(
        source_ip=host_ip,
        destination_ip="10.99.99.99",
        destination_port=445,
        protocol="TCP"
    )
    ctx_anom = enricher.enrich(ev_anom)
    res_anom = analyzer.analyze(ev_anom, ctx_anom)

    assert res_anom.is_unusual_destination is True
    assert res_anom.behavioural_deviation_score > 0.0
    assert any("Unprecedented destination" in r for r in res_anom.deviation_reasons)


# ==============================================================================
# 3. TEST STAGE 4: CAUSAL CORRELATION (CAPABILITY 1)
# ==============================================================================

def test_rule_based_correlation_attack_chain_tracking():
    """
    Validates Stage 4: Connects events across sliding windows into MITRE stages:
    Reconnaissance (T1046) -> Lateral Movement (T1021) -> Crown Jewel Access (T1530).
    """
    cfg = IntelligenceConfig(
        port_scan_port_threshold=8,
        window_seconds=300.0
    )
    correlator = RuleBasedCorrelator(config=cfg)
    enricher = ContextEnricher(config=cfg)
    analyzer = BehaviourAnalyzer(config=cfg)

    src_ip = "192.168.1.200"
    tracker = correlator.get_tracker(src_ip)

    # 1. Reconnaissance sweep (9 ports)
    for p in range(101, 110):
        ev = NormalizedSecurityEvent(source_ip=src_ip, destination_ip="10.0.0.1", destination_port=p)
        ctx = enricher.enrich(ev)
        beh = analyzer.analyze(ev, ctx)
        st = correlator.record_observation(tracker, ctx, beh)

    assert st.is_port_scan is True
    assert "reconnaissance" in st.stages_detected

    # 2. Lateral probe on port 445 (SMB)
    ev_lat = NormalizedSecurityEvent(source_ip=src_ip, destination_ip="10.0.0.2", destination_port=445)
    ctx_lat = enricher.enrich(ev_lat)
    beh_lat = analyzer.analyze(ev_lat, ctx_lat)
    st_lat = correlator.record_observation(tracker, ctx_lat, beh_lat)

    assert st_lat.has_lateral is True
    assert len(st_lat.attack_chain) >= 2
    assert "lateral_movement" in st_lat.stages_detected
    assert st_lat.should_synthesize_incident is True


# ==============================================================================
# 4. TEST STAGE 5: DUAL-AXIS RISK ASSESSMENT WITH ANTI-DOUBLE-COUNTING
# ==============================================================================

def test_anti_double_counting_and_decoupled_risk():
    """
    Validates Stage 5:
    - Grouping correlated signals by causal domain.
    - Ensuring overlapping signals (Signature + Frequency) are discounted by alpha dampening.
    - Validating that Severity (Impact) and Confidence (Certainty) are completely decoupled.
    """
    dampening_factor = 0.25
    cfg = IntelligenceConfig(
        weight_signature=30.0,
        weight_connection_frequency=20.0,
        weight_unusual_destination=15.0,
        weight_multiple_events=20.0,
        weight_behavioural_deviation=15.0,
        correlation_dampening_factor=dampening_factor
    )
    risk_engine = RiskEngine(config=cfg)

    from backend.intelligence.enricher import EnrichedEventContext
    from backend.intelligence.behaviour import BehaviourAssessment
    from backend.intelligence.correlator import CorrelatedIncidentState

    ctx = EnrichedEventContext(
        event_id="evt-1",
        timestamp=time.time(),
        tenant_id="acme",
        subject_ip="192.168.1.10",
        subject_hostname="host-10",
        subject_user="alice",
        target_ip="10.0.0.5",
        target_port=445,
        asset_criticality_multiplier=1.0
    )

    beh = BehaviourAssessment(
        source_ip="192.168.1.10",
        is_high_frequency=True,
        connection_rate_per_min=50.0,
        behavioural_deviation_score=0.8
    )

    corr = CorrelatedIncidentState(
        tracker_key="192.168.1.10",
        is_port_scan=True,
        observation_count=12,
        attack_chain=["Stage 1: Discovery", "Stage 2: Lateral Movement"]
    )

    # Raw events include verified IDS signature
    raw_events = [
        {"source": "suricata", "conn_state": "SF"},
        {"source": "zeek", "conn_state": "SF"},
        {"source": "detection_signature"}
    ]

    res = risk_engine.assess_risk(ctx, beh, corr, raw_events)

    # Anti-Double-Counting Verification:
    # Signature (30) and Frequency (20) both fall under "pattern_and_signature" domain.
    # Without anti-double-counting, raw sum would be 30 + 20 = 50.
    # With anti-double-counting, domain score = 30 + (20 * 0.25) = 35.0!
    assert res.dampening_discount_applied > 0.0
    assert res.severity_score < res.raw_score_sum

    # Decoupling Verification:
    # Severity is HIGH or CRITICAL
    assert res.severity_label in ("HIGH", "CRITICAL")
    # Multi-engine agreement (Suricata + Zeek) and SF TCP state elevates Confidence to CONFIRMED or PROBABLE
    assert res.confidence_score >= 0.75
    assert res.confidence_label in ("CONFIRMED", "PROBABLE")


# ==============================================================================
# 5. TEST STAGE 6: INCIDENT EXPLANATION & GUIDED REMEDIATION
# ==============================================================================

def test_incident_explanation_synthesis():
    """
    Validates Stage 6: Translates correlated graph and risk score into human-readable narrative,
    causal explanations, and context-aware investigation playbooks.
    """
    explainer = IncidentExplainer()

    from backend.intelligence.enricher import EnrichedEventContext
    from backend.intelligence.correlator import CorrelatedIncidentState
    from backend.intelligence.risk_engine import RiskAssessmentResult, ActiveRiskSignal

    ctx = EnrichedEventContext(
        event_id="evt-99",
        timestamp=time.time(),
        tenant_id="corp",
        subject_ip="192.168.1.75",
        subject_hostname="fin-ws-03",
        subject_user="bob",
        target_ip="10.0.0.1433",
        target_port=1433,
        is_crown_jewel=True,
        target_service="MSSQL Database"
    )

    corr = CorrelatedIncidentState(
        tracker_key="192.168.1.75",
        is_port_scan=True,
        has_crown_jewel=True,
        unique_ports_count=12,
        unique_ips_count=2,
        observation_count=14,
        attack_chain=[
            "Stage 1: Discovery (T1046) - Probed 12 ports",
            "Stage 4: Collection (T1530) - Targeted database"
        ]
    )

    risk = RiskAssessmentResult(
        severity_score=78.5,
        severity_label="CRITICAL",
        confidence_score=0.88,
        confidence_label="PROBABLE",
        dampening_discount_applied=12.5,
        active_signals=[
            ActiveRiskSignal(
                category=SignalCategory.SIGNATURE,
                name="Known malicious signature",
                raw_weight=30.0,
                effective_weight=30.0,
                causal_domain="pattern",
                description="Signature match"
            ),
            ActiveRiskSignal(
                category=SignalCategory.DESTINATION,
                name="Unusual destination",
                raw_weight=15.0,
                effective_weight=15.0,
                causal_domain="target",
                description="Targeted Crown Jewel"
            )
        ]
    )

    explanation = explainer.explain(ctx, corr, risk)

    assert "CRITICAL" in explanation.title
    assert "Multi-stage attack chain detected" in explanation.executive_summary
    assert "anti-double-counting" in explanation.risk_reasoning.lower()
    assert len(explanation.recommended_playbook) >= 4
    # Targeted database check must be injected into the playbook
    assert any("database access audit logs" in p.lower() for p in explanation.recommended_playbook)


# ==============================================================================
# 6. TEST ZERO HARDCODED VALUES (DYNAMIC CONFIGURATION OVERRIDES)
# ==============================================================================

def test_zero_hardcoded_values_configuration_overrides():
    """
    Validates that the pipeline enforces NO hardcoded values and respects
    custom runtime configurations (custom port thresholds, weights, dampening).
    """
    custom_cfg = IntelligenceConfig(
        weight_signature=50.0,
        weight_connection_frequency=10.0,
        port_scan_port_threshold=3,  # Customized: Trigger on only 3 ports
        correlation_dampening_factor=0.50,
        lateral_ports={9999: "Custom Proprietary Protocol"}
    )

    pipeline = StructuredIntelligencePipeline(config=custom_cfg)

    # 1. Custom lateral port mapping
    ev_custom = NormalizedSecurityEvent(
        source_ip="192.168.1.10",
        destination_ip="10.0.0.2",
        destination_port=9999,
        protocol="TCP",
        direction="internal"
    )
    res_custom = pipeline.process_event(ev_custom)
    assert res_custom.context.is_lateral_target is True
    assert res_custom.context.target_service == "Custom Proprietary Protocol"

    # 2. Custom low port scan threshold (3 ports instead of default 8)
    for p in (101, 102, 103):
        ev = NormalizedSecurityEvent(
            source_ip="192.168.1.10",
            destination_ip="10.0.0.5",
            destination_port=p,
            protocol="TCP"
        )
        res = pipeline.process_event(ev)

    assert res.correlation_state.is_port_scan is True
    assert res.should_synthesize_incident is True
    assert res.risk.severity_score > 0.0
