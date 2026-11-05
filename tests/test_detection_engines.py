import time
import pytest
from backend.pipeline.schemas import (
    NormalizedSecurityEvent,
    format_utc_timestamp,
    get_utc_iso_now
)
from backend.detection.models import DetectionEngineType, DetectionFinding
from backend.detection.signature_engine import SignatureEngine
from backend.detection.rule_engine import RuleEngine, shannon_entropy
from backend.detection.behaviour_engine import BehaviourEngine, RunningStats
from backend.detection.detection_manager import DetectionManager

def test_signature_engine():
    engine = SignatureEngine()

    # Suricata EVE Alert Event
    event = NormalizedSecurityEvent(
        source_ip="192.168.1.50",
        destination_ip="192.168.1.10",
        source_port=49152,
        destination_port=445,
        protocol="TCP",
        event_type="alert",
        detection_source="suricata",
        severity="HIGH",
        rule_id="SID:2010935",
        evidence={
            "signature": "ET EXPLOIT Possible Lateral Movement via SMB Exec",
            "category": "Attempted Administrator Privilege Gain",
            "severity_level": 1
        }
    )

    findings = engine.analyze(event)
    assert len(findings) == 1
    f = findings[0]
    assert f.engine_type == DetectionEngineType.SIGNATURE
    assert "2010935" in f.rule_id
    assert f.mitre_technique == "T1021 Remote Services"
    assert f.mitre_stage == "lateral_movement"
    assert f.severity == "HIGH"
    assert f.confidence >= 0.90

def test_rule_engine_port_scan():
    # Lower threshold for deterministic testing
    engine = RuleEngine(window_seconds=30.0, port_scan_threshold=5, cooldown_seconds=0.0)

    findings = []
    # Probe 6 distinct ports
    for p in range(1001, 1007):
        ev = NormalizedSecurityEvent(
            source_ip="10.0.0.99",
            destination_ip="10.0.0.1",
            source_port=55000 + p,
            destination_port=p,
            protocol="TCP",
            event_type="connection",
            detection_source="zeek"
        )
        res = engine.analyze(ev)
        if res:
            findings.extend(res)

    assert len(findings) >= 1
    scan_finding = next((f for f in findings if f.rule_id == "NETRIQ:RULE:PORT_SCAN_RECON"), None)
    assert scan_finding is not None
    assert scan_finding.engine_type == DetectionEngineType.RULE
    assert scan_finding.mitre_technique == "T1046 Network Service Discovery"
    assert scan_finding.evidence["unique_ports_count"] >= 5

def test_rule_engine_dns_tunneling():
    engine = RuleEngine(window_seconds=30.0, cooldown_seconds=0.0)

    # High entropy domain (simulated base64 DNS tunneling)
    tunnel_domain = "a8f7c9e1b2d3f4a5b6c7d8e9f0a1b2c3d4e5f6.tunnel.darknet.org"
    ev = NormalizedSecurityEvent(
        source_ip="192.168.1.105",
        destination_ip="8.8.8.8",
        source_port=53535,
        destination_port=53,
        protocol="DNS",
        event_type="connection",
        detection_source="zeek",
        evidence={
            "dns_query": tunnel_domain,
            "qtype_name": "TXT"
        }
    )

    findings = engine.analyze(ev)
    assert len(findings) == 1
    dns_finding = findings[0]
    assert dns_finding.rule_id == "NETRIQ:RULE:UNUSUAL_DNS_ACTIVITY"
    assert dns_finding.evidence["is_tunnel_indicator"] is True
    assert dns_finding.evidence["entropy"] > 3.8

def test_rule_engine_failed_connections():
    engine = RuleEngine(window_seconds=30.0, failed_conn_threshold=3, cooldown_seconds=0.0)

    findings = []
    # 3 consecutive S0 unresponded attempts to SMB port 445
    for _ in range(3):
        ev = NormalizedSecurityEvent(
            source_ip="192.168.1.185",
            destination_ip="192.168.1.10",
            source_port=50000,
            destination_port=445,
            protocol="TCP",
            event_type="connection",
            detection_source="zeek",
            evidence={
                "conn_state": "S0"
            }
        )
        res = engine.analyze(ev)
        if res:
            findings.extend(res)

    assert len(findings) >= 1
    churn_finding = next((f for f in findings if f.rule_id == "NETRIQ:RULE:FAILED_CONNECTION_CHURN"), None)
    assert churn_finding is not None
    assert churn_finding.severity == "HIGH" # Triggered by sensitive admin port 445
    assert churn_finding.evidence["has_admin_ports"] is True

def test_behaviour_engine_statistical_baseline_and_anomaly():
    # Use 10 learning samples for test speed
    engine = BehaviourEngine(
        min_learning_samples=10,
        z_score_threshold=3.0,
        min_anomalous_bytes=20000,
        alert_cooldown_seconds=0.0
    )

    # 1. Establish normal baseline (~1,000 to 2,000 bytes per flow)
    for _ in range(12):
        ev_normal = NormalizedSecurityEvent(
            source_ip="192.168.1.200",
            destination_ip="93.184.216.34",
            destination_port=443,
            direction="outbound",
            evidence={"orig_bytes": 1500}
        )
        findings = engine.analyze(ev_normal)
        assert len(findings) == 0 # In baseline learning phase

    profile = engine._get_profile("192.168.1.200")
    assert profile.is_baseline_ready is True
    assert 1400 < profile.egress_bytes_stats.mean < 1600

    # 2. Trigger huge anomalous exfiltration burst (1,000,000 bytes)
    ev_exfil = NormalizedSecurityEvent(
        source_ip="192.168.1.200",
        destination_ip="198.51.100.99",
        destination_port=443,
        direction="outbound",
        evidence={"orig_bytes": 1000000}
    )
    findings = engine.analyze(ev_exfil)
    assert len(findings) >= 1
    egress_finding = next((f for f in findings if f.rule_id == "NETRIQ:BEHAVIOUR:ANOMALOUS_EGRESS_VOLUME"), None)
    assert egress_finding is not None
    assert egress_finding.engine_type == DetectionEngineType.BEHAVIOUR
    assert egress_finding.evidence["z_score"] > 5.0
    assert egress_finding.severity == "HIGH"
    assert egress_finding.mitre_technique == "T1048 Exfiltration Over Alternative Protocol"

def test_behaviour_engine_novel_port():
    engine = BehaviourEngine(min_learning_samples=5, alert_cooldown_seconds=0.0)

    # Learn normal web ports
    for p in (80, 443, 53, 80, 443, 53):
        ev = NormalizedSecurityEvent(
            source_ip="192.168.1.210",
            destination_ip="1.1.1.1",
            destination_port=p,
            evidence={"orig_bytes": 100}
        )
        engine.analyze(ev)

    # Connect to high-risk novel port (Metasploit reverse handler 4444)
    ev_novel = NormalizedSecurityEvent(
        source_ip="192.168.1.210",
        destination_ip="198.51.100.5",
        destination_port=4444,
        evidence={"orig_bytes": 200}
    )
    findings = engine.analyze(ev_novel)
    assert len(findings) >= 1
    novel_finding = next((f for f in findings if f.rule_id == "NETRIQ:BEHAVIOUR:NOVEL_PORT_COMMUNICATION"), None)
    assert novel_finding is not None
    assert novel_finding.evidence["novel_port"] == 4444
    assert novel_finding.evidence["is_high_risk_signature_port"] is True
    assert novel_finding.severity == "HIGH"

def test_detection_manager_orchestration():
    manager = DetectionManager()

    # Event with Suricata alert AND novel port
    event = NormalizedSecurityEvent(
        source_ip="10.10.10.5",
        destination_ip="198.51.100.77",
        source_port=60000,
        destination_port=8443,
        protocol="TCP",
        event_type="alert",
        detection_source="suricata",
        severity="CRITICAL",
        evidence={
            "signature": "ET TROJAN Cobalt Strike Beaconing Observed",
            "category": "A Network Trojan was detected",
            "severity_level": 1
        }
    )

    findings = manager.evaluate(event)
    assert len(findings) >= 1
    sig_finding = next((f for f in findings if f.engine_type == DetectionEngineType.SIGNATURE), None)
    assert sig_finding is not None
    assert "Cobalt Strike" in sig_finding.title
