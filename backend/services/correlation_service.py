import time
import collections
from typing import Dict, List, Any, Optional

from backend.utils.logger import get_logger
from backend.pipeline.schemas import NormalizedSecurityEvent, EventType
from backend.database.collections import incidents_repo
from backend.services.notification_service import notification_service

logger = get_logger(__name__)

# Port Classifications
LATERAL_PORTS = {
    445: "SMB / File Sharing",
    135: "RPC Endpoint Mapper",
    139: "NetBIOS Session Service",
    3389: "RDP Remote Desktop",
    22: "SSH Remote Shell",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    21: "FTP Control",
    23: "Telnet"
}

CROWN_JEWEL_PORTS = {
    1433: "MSSQL Database",
    3306: "MySQL Database",
    5432: "PostgreSQL Database",
    27017: "MongoDB Cluster",
    6379: "Redis In-Memory Store",
    88: "Kerberos Key Distribution",
    389: "LDAP Directory Service",
    636: "LDAPS Secure Directory"
}

CRITICAL_TOOLS = {
    "mimikatz.exe": "T1003 OS Credential Dumping",
    "nmap.exe": "T1046 Network Service Discovery",
    "responder.py": "T1557 LLMNR/NBT-NS Poisoning",
    "cobaltstrike": "T1071 Command and Control Beacon",
    "psexec.exe": "T1569 Lateral Tool Execution",
    "hydra.exe": "T1110 Brute Force Password Cracker",
    "wireshark.exe": "T1040 Network Sniffing",
    "chisel.exe": "T1572 Protocol Tunneling / Proxy"
}

class DeviceActivityTracker:
    def __init__(self, key: str, window_seconds: float = 600.0):
        self.key = key
        self.window_seconds = window_seconds
        self.events: collections.deque = collections.deque()
        self.scanned_ports: set = set()
        self.scanned_ips: set = set()
        self.lateral_attempts: List[Dict[str, Any]] = []
        self.crown_jewel_attempts: List[Dict[str, Any]] = []
        self.c2_attempts: List[Dict[str, Any]] = []
        self.suspicious_processes: List[Dict[str, Any]] = []
        self.active_incident_id: Optional[str] = None
        self.last_updated: float = time.time()

    def prune(self, now: float):
        cutoff = now - self.window_seconds
        while self.events and self.events[0]["timestamp"] < cutoff:
            self.events.popleft()

        # Recalculate working sets
        self.scanned_ports = {e["dst_port"] for e in self.events if e.get("dst_port")}
        self.scanned_ips = {e["dst_ip"] for e in self.events if e.get("dst_ip")}
        self.lateral_attempts = [e for e in self.events if e.get("stage") == "lateral_movement"]
        self.crown_jewel_attempts = [e for e in self.events if e.get("stage") == "crown_jewel_access"]
        self.c2_attempts = [e for e in self.events if e.get("stage") == "c2_exfil"]
        self.suspicious_processes = [e for e in self.events if e.get("stage") == "malicious_process"]

class CorrelationEngine:
    """
    Layer 4 Intelligence-Driven Intrusion Detection Engine.
    Executes the 7-Step Sequence:
    1. Detect port scan / anomalous activity
    2. Identify source and destination (host, user, MAC, role)
    3. Examine connection patterns (frequency, target services, flags)
    4. Correlate related observations across sliding windows
    5. Determine attack chain (MITRE ATT&CK progression)
    6. Calculate contextual severity
    7. Generate structured evidence and guided SOC response playbook
    """

    def __init__(self, window_seconds: float = 600.0):
        self.window_seconds = window_seconds
        self._trackers: Dict[str, DeviceActivityTracker] = {}

    def _get_tracker(self, key: str) -> DeviceActivityTracker:
        now = time.time()
        if key not in self._trackers:
            self._trackers[key] = DeviceActivityTracker(key, self.window_seconds)
        tracker = self._trackers[key]
        tracker.prune(now)
        tracker.last_updated = now
        return tracker

    async def process_detection(self, finding: Any, event: NormalizedSecurityEvent):
        """
        Ingests a high-fidelity DetectionFinding from Layer 3 (Signature, Rule, or Behaviour Engine)
        and correlates it into the device's attack timeline.
        """
        try:
            device_key = (event.device.ip if event.device else None) or finding.source_ip or event.source_ip or "unknown"
            if device_key in ("unknown", "127.0.0.1", "0.0.0.0"):
                return

            now = time.time()
            tracker = self._get_tracker(device_key)

            stage = finding.mitre_stage or "reconnaissance"
            engine_str = getattr(finding.engine_type, "value", str(finding.engine_type))
            evidence_item = {
                "event_id": event.event_id,
                "finding_id": finding.finding_id,
                "timestamp": now,
                "type": f"detection_{engine_str}",
                "source": engine_str,
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "src_ip": finding.source_ip,
                "dst_ip": finding.destination_ip,
                "dst_port": finding.destination_port,
                "protocol": finding.protocol,
                "stage": stage,
                "mitre": finding.mitre_technique or "T1046 Network Service Discovery",
                "summary": finding.description,
                "details": finding.evidence
            }

            tracker.events.append(evidence_item)
            tracker.prune(now)
            await self._evaluate_and_synthesize_incident(tracker, event)
        except Exception as e:
            logger.error(f"[CorrelationEngine] Error processing detection finding: {e}", exc_info=True)

    async def process_event(self, event: NormalizedSecurityEvent):
        """Asynchronous callback subscribed to the SecurityEventBus."""
        try:
            device_key = (event.device.ip if event.device else None) or event.source_ip or "unknown"
            if device_key == "unknown" or device_key == "127.0.0.1":
                return

            # 0. Dispatch to Layer 3 Detection Engines (Signature, Rule, Behaviour)
            try:
                from backend.detection import detection_manager
                findings = detection_manager.evaluate(event)
                for finding in findings:
                    await self.process_detection(finding, event)
            except Exception as det_err:
                logger.debug(f"[CorrelationEngine] Layer 3 detection evaluation error: {det_err}")

            now = time.time()
            tracker = self._get_tracker(device_key)

            stage = None
            ev_type_str = getattr(event.event_type, "value", event.event_type)
            ev_source_str = getattr(event.detection_source, "value", event.detection_source)

            evidence_item = {
                "event_id": event.event_id,
                "timestamp": now,
                "type": ev_type_str,
                "source": ev_source_str
            }

            # 1. Step 1-3: Detect, Identify, Examine Network Flows
            if event.source_ip and event.destination_ip:
                dst_ip = event.destination_ip
                dst_port = event.destination_port or 0
                evidence_item["src_ip"] = event.source_ip
                evidence_item["dst_ip"] = dst_ip
                evidence_item["dst_port"] = dst_port
                evidence_item["protocol"] = event.protocol

                # Check Crown Jewel / Database access
                if dst_port in CROWN_JEWEL_PORTS and event.network.direction == "internal":
                    service_desc = CROWN_JEWEL_PORTS[dst_port]
                    stage = "crown_jewel_access"
                    evidence_item["stage"] = stage
                    evidence_item["mitre"] = "T1530 Data from Cloud/Internal Storage"
                    evidence_item["summary"] = f"Internal probe to high-value service ({service_desc}) on {dst_ip}:{dst_port}"

                # Check Lateral Movement ports
                elif dst_port in LATERAL_PORTS and event.network.direction == "internal":
                    service_desc = LATERAL_PORTS[dst_port]
                    stage = "lateral_movement"
                    evidence_item["stage"] = stage
                    evidence_item["mitre"] = "T1021 Remote Services"
                    evidence_item["summary"] = f"Internal lateral movement probe to {service_desc} on {dst_ip}:{dst_port}"

                # Check C2 / Outbound non-standard traffic
                elif event.network.direction == "outbound" and dst_port not in (80, 443, 53, 123):
                    stage = "c2_exfil"
                    evidence_item["stage"] = stage
                    evidence_item["mitre"] = "T1071 Application Layer Protocol"
                    evidence_item["summary"] = f"Unusual outbound connection to external remote service {dst_ip}:{dst_port}"

                # Reconnaissance / Port Scan
                else:
                    stage = "reconnaissance"
                    evidence_item["stage"] = stage
                    evidence_item["mitre"] = "T1046 Network Service Discovery"
                    evidence_item["summary"] = f"Port probe against {dst_ip}:{dst_port}"

            # 2. Step 1-3: Detect, Identify, Examine Endpoint Activity
            elif event.endpoint:
                proc_name = (event.endpoint.process_name or "").lower()
                evidence_item["process_name"] = proc_name
                evidence_item["pid"] = event.endpoint.pid

                if proc_name in CRITICAL_TOOLS or event.endpoint.is_suspicious:
                    mitre_code = CRITICAL_TOOLS.get(proc_name, "T1059 Command Execution")
                    stage = "malicious_process"
                    evidence_item["stage"] = stage
                    evidence_item["mitre"] = mitre_code
                    evidence_item["summary"] = f"Known offensive / penetration binary execution: {proc_name} ({mitre_code})"

                elif event.event_type in ("network_connection", "connection"):
                    r_port = event.endpoint.remote_port or 0
                    if r_port in LATERAL_PORTS:
                        stage = "lateral_movement"
                        evidence_item["stage"] = stage
                        evidence_item["mitre"] = "T1021 Remote Services"
                        evidence_item["summary"] = f"Endpoint socket connection to sensitive lateral port {r_port}"

            if stage:
                tracker.events.append(evidence_item)
                tracker.prune(now)
                # Step 4, 5, 6, 7: Correlate, Attack Chain, Severity, and Investigation Steps
                await self._evaluate_and_synthesize_incident(tracker, event)

        except Exception as e:
            logger.error(f"[CorrelationEngine] Error in correlation pipeline: {e}", exc_info=True)

    async def _evaluate_and_synthesize_incident(self, tracker: DeviceActivityTracker, latest_event: NormalizedSecurityEvent):
        """
        Step 4-7:
        4. Correlates related observations across the device tracker.
        5. Determines if activity is part of a larger multi-stage attack.
        6. Calculates contextual severity.
        7. Produces supporting evidence and guided investigation steps.
        """
        unique_ports = len(tracker.scanned_ports)
        unique_ips = len(tracker.scanned_ips)
        has_lateral = len(tracker.lateral_attempts) > 0
        has_crown_jewel = len(tracker.crown_jewel_attempts) > 0
        has_c2 = len(tracker.c2_attempts) > 0
        has_malicious_proc = len(tracker.suspicious_processes) > 0

        # Step 4: Examine Reconnaissance threshold
        is_port_scan = unique_ports >= 8 or unique_ips >= 5

        # Step 5: Attack Chain Synthesis (MITRE ATT&CK Mapping)
        attack_chain: List[str] = []
        if is_port_scan:
            attack_chain.append(f"Stage 1: Discovery (T1046) - Probed {unique_ports} ports across {unique_ips} hosts")
        if has_malicious_proc:
            proc_names = list({p.get('process_name') for p in tracker.suspicious_processes if p.get('process_name')})
            attack_chain.append(f"Stage 2: Execution (T1059) - Offensive tooling launched ({', '.join(proc_names)})")
        if has_lateral:
            attack_chain.append(f"Stage 3: Lateral Movement (T1021) - {len(tracker.lateral_attempts)} sensitive service probes")
        if has_crown_jewel:
            attack_chain.append(f"Stage 4: Collection (T1530) - Targeted high-value internal database/auth assets")
        if has_c2:
            attack_chain.append(f"Stage 5: Command & Control (T1071) - Anomalous outbound communication established")

        # Must meet correlation criteria: 2+ stages OR critical offensive process OR port scan OR 3+ correlated observations
        obs_count = len(tracker.events)
        should_trigger = len(attack_chain) >= 2 or has_malicious_proc or is_port_scan or obs_count >= 3
        if not should_trigger:
            return

        # Step 6A: Contextual Severity Calculation (Impact / Business Risk)
        # Context Factors: stages count, crown jewel presence, user elevation
        device = latest_event.device
        is_elevated = bool(device and getattr(device, "logged_in_user", None) in ("root", "Administrator"))
        
        severity_score = 0
        if has_crown_jewel:
            severity_score += 40
        if has_c2:
            severity_score += 30
        if has_lateral:
            severity_score += 25
        if has_malicious_proc:
            severity_score += 25
        if is_port_scan:
            severity_score += 15
        if is_elevated:
            severity_score += 15

        # Multi-stage amplifier
        if len(attack_chain) >= 2:
            severity_score += (len(attack_chain) - 1) * 10

        if severity_score >= 65 or has_crown_jewel or len(attack_chain) >= 3:
            severity = "CRITICAL"
        elif severity_score >= 40:
            severity = "HIGH"
        elif severity_score >= 20:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Step 6B: Evidentiary Confidence Calculation (Certainty / Proof of Occurrence)
        # Independent of Severity: evaluating sensor agreement, repetition count, and TCP states
        sources = {e.get("source") for e in tracker.events if e.get("source")}
        engine_count = len(sources)

        # Baseline confidence from observation volume
        if obs_count >= 10:
            conf_score = 0.75
        elif obs_count >= 5:
            conf_score = 0.65
        elif obs_count >= 3:
            conf_score = 0.55
        else:
            conf_score = 0.45

        # Multi-engine corroboration bonus
        if engine_count >= 3:
            conf_score += 0.20 # Suricata + Zeek + NetrIQ Rule/Behaviour all agree
        elif engine_count == 2:
            conf_score += 0.12 # e.g. Zeek + Suricata agree

        # Handshake / Exploit confirmation check
        has_established_session = any(
            e.get("details", {}).get("conn_state") == "SF" or e.get("conn_state") == "SF"
            for e in tracker.events
        )
        has_verified_signature = any(
            e.get("source") in ("suricata", "detection_signature")
            for e in tracker.events
        )
        if has_established_session and has_verified_signature:
            conf_score += 0.15
        elif has_established_session:
            conf_score += 0.08

        # Clamp between 0.35 and 0.99
        confidence = round(max(0.35, min(0.99, conf_score)), 2)

        # Qualitative Confidence Label
        if confidence >= 0.90:
            confidence_label = "CONFIRMED"
        elif confidence >= 0.75:
            confidence_label = "PROBABLE"
        elif confidence >= 0.60:
            confidence_label = "SUSPECTED"
        else:
            confidence_label = "NEEDS_VALIDATION"

        # Determine Incident Classification / Title
        if len(attack_chain) >= 2:
            incident_type = f"Correlated Attack Chain: {' -> '.join([s.split(' - ')[0] for s in attack_chain])}"
        elif has_crown_jewel:
            incident_type = "Crown Jewel Access Attempt"
        elif has_lateral:
            incident_type = "Lateral Movement Activity"
        elif has_c2:
            incident_type = "Suspected C2 Communication"
        elif has_malicious_proc:
            incident_type = "Malicious Process Execution"
        elif is_port_scan or obs_count >= 3:
            incident_type = "Possible reconnaissance"
        else:
            incident_type = "Suspicious Network Activity"

        # Step 7: Formulate Recommended Investigation Steps (Actionable SOC Playbook)
        hostname = (device.hostname if device else None) or "the host"
        ip = (device.ip if device else None) or tracker.key
        user = (device.logged_in_user if device else None) or "active session"

        investigation_steps = [
            f"1. Isolate {hostname} ({ip}) immediately using NetrIQ 1-Click Endpoint Quarantine to block lateral spread.",
            f"2. Audit active processes on {hostname}; inspect parent-child execution trees for flagged binaries.",
            f"3. Verify authentication logs for user '{user}' across internal directory and database servers.",
            f"4. Block targeted destination ports on the perimeter firewall and review connection egress."
        ]

        if has_crown_jewel:
            investigation_steps.insert(2, f"Targeted high-value internal asset detected: Check database access audit logs for unauthorized queries.")

        title = f"{incident_type} ({severity})"

        await self._upsert_incident(
            tracker=tracker,
            event=latest_event,
            title=title,
            incident_type=incident_type,
            severity=severity,
            confidence=confidence,
            confidence_label=confidence_label,
            attack_chain=attack_chain,
            investigation_steps=investigation_steps
        )

    async def _upsert_incident(
        self,
        tracker: DeviceActivityTracker,
        event: NormalizedSecurityEvent,
        title: str,
        incident_type: str,
        severity: str,
        confidence: float,
        confidence_label: str,
        attack_chain: List[str],
        investigation_steps: List[str]
    ):
        """Persists or updates an active Incident with full intelligence context in MongoDB."""
        now = time.time()
        device = event.device
        target_ip = (device.ip if device else None) or event.source_ip or tracker.key
        target_hostname = (device.hostname if device else None) or "Unknown Host"
        target_mac = (device.mac if device else None) or "Unknown MAC"
        target_user = (device.logged_in_user if device else None) or "Unknown User"

        evidence_slice = list(tracker.events)[-20:]

        if tracker.active_incident_id:
            try:
                await incidents_repo.update(tracker.active_incident_id, {
                    "updated_at": now,
                    "event_count": len(tracker.events),
                    "severity": severity,
                    "confidence": confidence,
                    "confidence_label": confidence_label,
                    "incident_type": incident_type,
                    "description": title,
                    "attack_chain": attack_chain,
                    "evidence": evidence_slice,
                    "recommended_investigation_steps": investigation_steps
                })
                logger.info(f"[CorrelationEngine] Updated Incident {tracker.active_incident_id} with {len(attack_chain)} attack stages.")
                return
            except Exception:
                pass

        # Create New Incident
        incident_doc = {
            "tenant_id": event.tenant_id or "default",
            "status": "new",
            "incident_type": incident_type,
            "severity": severity,
            "title": title,
            "description": title,
            "attack_chain": attack_chain,
            "created_at": now,
            "updated_at": now,
            "event_count": len(tracker.events),
            "affected_assets": [target_ip, target_hostname, target_mac],
            "src_ip": target_ip,
            "hostname": target_hostname,
            "mac": target_mac,
            "user": target_user,
            "confidence": confidence,
            "confidence_label": confidence_label,
            "evidence": evidence_slice,
            "recommended_investigation_steps": investigation_steps,
            "response_action": "quarantine_recommended" if severity == "CRITICAL" else "alert_analyst",
            "response_success": True
        }

        try:
            inc_id = await incidents_repo.create(incident_doc)
            tracker.active_incident_id = inc_id
            incident_doc["id"] = inc_id
            logger.info(f"[CorrelationEngine] Generated Intelligence Incident {inc_id} ({severity}) for {target_ip}")

            # Realtime broadcast to SOC Analyst Dashboard via WebSocket
            await notification_service.notify_new_incident(incident_doc)
        except Exception as e:
            logger.error(f"[CorrelationEngine] Failed to persist incident: {e}", exc_info=True)

correlation_engine = CorrelationEngine()
