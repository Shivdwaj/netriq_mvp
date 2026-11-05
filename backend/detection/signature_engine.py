from typing import List, Optional, Dict, Any
from backend.detection.models import DetectionFinding, DetectionEngineType
from backend.pipeline.schemas import NormalizedSecurityEvent
from backend.utils.logger import get_logger

logger = get_logger(__name__)

class SignatureEngine:
    """
    Engine 1: Signature Engine
    Consumes Suricata alerts and identifies known threat patterns (CVEs, malware C2, exploits).
    Produces standardized DetectionFindings for downstream Layer 4 correlation.
    """

    @staticmethod
    def _map_mitre_and_stage(category: str, signature: str) -> tuple[Optional[str], Optional[str]]:
        """Maps Suricata ET category and signature string to MITRE technique and attack stage."""
        sig_lower = (signature or "").lower()
        cat_lower = (category or "").lower()

        # 1. Discovery / Scans
        if any(k in sig_lower for k in ("scan", "nmap", "portscan", "masscan")):
            return "T1046 Network Service Discovery", "discovery"

        # 2. Lateral Movement (Checked before generic exploit to catch 'ET EXPLOIT Lateral SMB')
        if any(k in sig_lower for k in ("lateral", "smb", "rdp", "psexec", "wmi exec", "dcom")):
            return "T1021 Remote Services", "lateral_movement"

        # 3. Credential Access / Dumping
        if any(k in sig_lower for k in ("credential", "mimikatz", "dump", "lsass", "kerberoast")):
            return "T1003 OS Credential Dumping", "credential_access"

        # 4. Command and Control (C2) / Beacons
        if any(k in sig_lower for k in ("c2", "beacon", "trojan", "cobalt", "meterpreter", "empire")):
            return "T1071 Application Layer Protocol", "c2_exfil"

        # 5. Initial Access / Exploits / RCE
        if any(k in sig_lower for k in ("exploit", "cve-", "rce", "remote code execution", "overflow")):
            return "T1190 Exploit Public-Facing Application", "initial_access"

        # 6. Exfiltration
        if any(k in sig_lower for k in ("exfiltration", "upload", "data transfer", "tunnel")):
            return "T1048 Exfiltration Over Alternative Protocol", "c2_exfil"

        # Category fallbacks
        if "trojan" in cat_lower or "malware" in cat_lower:
            return "T1071 Application Layer Protocol", "c2_exfil"
        if "exploit" in cat_lower or "vulnerability" in cat_lower:
            return "T1190 Exploit Public-Facing Application", "initial_access"

        return None, None

    def analyze(self, event: NormalizedSecurityEvent) -> List[DetectionFinding]:
        """
        Evaluates a normalized security event.
        If the event contains a signature alert (from Suricata or rule engine), generates a finding.
        """
        findings: List[DetectionFinding] = []

        is_suricata = str(event.detection_source).lower() == "suricata"
        is_alert = str(event.event_type).lower() == "alert"
        has_sig = bool(event.evidence.get("signature") or (event.rule_id and event.rule_id.startswith("SID:")))

        if not (is_suricata or is_alert or has_sig):
            return findings

        # Extract signature details from evidence dictionary
        signature = event.evidence.get("signature") or f"Alert on {event.destination_ip}:{event.destination_port}"
        category = event.evidence.get("category", "Potentially Bad Traffic")
        sig_id = event.evidence.get("signature_id") or event.rule_id or "UNKNOWN"
        mitre_tech, mitre_stage = self._map_mitre_and_stage(category, signature)

        # Baseline confidence based on severity level
        severity = event.severity.upper() if event.severity else "MEDIUM"
        confidence_map = {
            "CRITICAL": 0.98,
            "HIGH": 0.92,
            "MEDIUM": 0.85,
            "LOW": 0.70,
            "INFO": 0.50
        }
        confidence = confidence_map.get(severity, 0.80)

        finding = DetectionFinding(
            engine_type=DetectionEngineType.SIGNATURE,
            rule_id=f"SURICATA:{sig_id}",
            title=f"Signature Match: {signature}",
            description=f"Suricata detected known signature [{signature}] in category [{category}].",
            severity=severity,
            confidence=confidence,
            mitre_technique=mitre_tech,
            mitre_stage=mitre_stage,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            source_port=event.source_port,
            destination_port=event.destination_port,
            protocol=event.protocol,
            timestamp=event.timestamp,
            evidence={
                "signature": signature,
                "category": category,
                "signature_id": sig_id,
                "suricata_severity": event.evidence.get("severity_level"),
                "raw_alert": event.evidence
            },
            matched_event_ids=[event.event_id]
        )

        findings.append(finding)
        return findings

signature_engine = SignatureEngine()
