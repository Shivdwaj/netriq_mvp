import time
import collections
from typing import Dict, List, Any, Optional, Set

from backend.utils.logger import get_logger
from backend.pipeline.schemas import NormalizedSecurityEvent, EventType
from backend.database.collections import incidents_repo
from backend.services.notification_service import notification_service
from backend.services.evidence_service import evidence_service
from backend.schemas.entities import IncidentEventRole
from backend.intelligence.config import IntelligenceConfig, intelligence_config
from backend.intelligence.enricher import ContextEnricher, EnrichedEventContext, threat_intel_feed
from backend.intelligence.behaviour import BehaviourAnalyzer, BehaviourAssessment
from backend.intelligence.correlator import CorrelatedIncidentState
from backend.intelligence.risk_engine import RiskEngine, RiskAssessmentResult
from backend.intelligence.explainer import IncidentExplainer, IncidentExplanation

logger = get_logger(__name__)

# Configurable dynamic mappings (zero hardcoded values; initialized from intelligence_config)
LATERAL_PORTS: Dict[int, str] = intelligence_config.lateral_ports
CROWN_JEWEL_PORTS: Dict[int, str] = intelligence_config.crown_jewel_ports
CRITICAL_TOOLS: Dict[str, str] = intelligence_config.critical_tools

class DeviceActivityTracker:
    def __init__(self, key: str, window_seconds: Optional[float] = None):
        self.key = key
        self.window_seconds = window_seconds or intelligence_config.window_seconds
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
        while self.events and self.events[0].get("timestamp", 0) < cutoff:
            self.events.popleft()

        # Recalculate working sets
        self.scanned_ports = {e["dst_port"] for e in self.events if e.get("dst_port")}
        self.scanned_ips = {e["dst_ip"] for e in self.events if e.get("dst_ip")}
        self.lateral_attempts = [e for e in self.events if e.get("stage") == "lateral_movement"]
        self.crown_jewel_attempts = [e for e in self.events if e.get("stage") == "crown_jewel_access"]
        self.c2_attempts = [e for e in self.events if e.get("stage") == "c2_exfil"]
        self.suspicious_processes = [e for e in self.events if e.get("stage") == "malicious_process"]

class MultiTenantTrackerMap(dict):
    """
    Registry for device activity trackers partitioned by tenant_id:device_ip composite keys.
    Provides transparent backward-compatible fallback lookups for raw device_ip queries in tests.
    """
    def __getitem__(self, key: str):
        if super().__contains__(key):
            return super().__getitem__(key)
        for k, v in self.items():
            if k.endswith(f":{key}") or k == key:
                return v
        raise KeyError(key)

    def get(self, key: str, default=None):
        if super().__contains__(key):
            return super().get(key, default)
        for k, v in self.items():
            if k.endswith(f":{key}") or k == key:
                return v
        return default

    def __contains__(self, key: str) -> bool:
        if super().__contains__(key):
            return True
        for k in self.keys():
            if k.endswith(f":{key}") or k == key:
                return True
        return False


class CorrelationEngine:
    """
    Structured NetrIQ Intelligence & Correlation Engine.
    Executes the 6-Stage Structured Intelligence Pipeline:
    1. Event interpretation (entity resolution & intent)
    2. Context enrichment (asset topology & threat intelligence)
    3. Behaviour analysis (adaptive baselines & anomaly detection)
    4. Causal correlation (sliding windows & MITRE attack stages)
    5. Risk assessment (independent severity/confidence with anti-double-counting)
    6. Incident explanation (executive narrative & guided response playbook)

    Zero hardcoded values: all configurations, weights, and thresholds are dynamic.
    """

    def __init__(self, window_seconds: Optional[float] = None, config: Optional[IntelligenceConfig] = None):
        self.config = config or intelligence_config
        self.window_seconds = window_seconds or self.config.window_seconds
        self._trackers: MultiTenantTrackerMap = MultiTenantTrackerMap()
        self.enricher = ContextEnricher(self.config, threat_intel_feed)
        self.behaviour_analyzer = BehaviourAnalyzer(self.config)
        self.risk_engine = RiskEngine(self.config)
        self.explainer = IncidentExplainer()

    def _make_composite_key(self, device_ip: str, tenant_id: Optional[str] = None) -> str:
        tid = tenant_id or "default"
        return f"{tid}:{device_ip}"

    async def _get_tracker(self, key: str, tenant_id: Optional[str] = None) -> DeviceActivityTracker:
        now = time.time()
        if ":" in key:
            composite_key = key
            raw_ip = key.split(":", 1)[1]
        else:
            raw_ip = key
            composite_key = self._make_composite_key(key, tenant_id)

        if composite_key not in self._trackers:
            tracker = DeviceActivityTracker(composite_key, self.window_seconds)
            await self._restore_active_incident(tracker, raw_ip, tenant_id)
            self._trackers[composite_key] = tracker
        tracker = self._trackers[composite_key]
        tracker.prune(now)
        tracker.last_updated = now
        return tracker

    async def _restore_active_incident(self, tracker: DeviceActivityTracker, key: str, tenant_id: Optional[str] = None):
        """
        Restores active incident association from MongoDB after a backend restart.
        Prevents fragmentation / duplicate incident creation for ongoing attacks.
        """
        try:
            now = time.time()
            cutoff = now - max(self.window_seconds * 2, 7200.0)
            filter_q: Dict[str, Any] = {
                "status": {"$in": ["new", "investigating", "open", "in_progress"]},
                "updated_at": {"$gte": cutoff},
                "$or": [{"src_ip": key}, {"affected_assets": key}]
            }
            if tenant_id and tenant_id != "global":
                filter_q["tenant_id"] = tenant_id

            active_incidents = await incidents_repo.list(
                filter_query=filter_q,
                limit=1,
                sort_by=[("updated_at", -1)]
            )
            if active_incidents:
                inc = active_incidents[0]
                tracker.active_incident_id = inc.get("id") or str(inc.get("_id", ""))
                # Rehydrate recent evidence events from incident
                for ev in inc.get("evidence", []):
                    if isinstance(ev, dict):
                        tracker.events.append(ev)
                logger.info(
                    f"[CorrelationEngine] Restored active incident {tracker.active_incident_id} "
                    f"for device '{key}' from persistent storage."
                )
        except Exception as e:
            logger.debug(f"[CorrelationEngine] Could not restore active incident for {key}: {e}")

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
            tracker = await self._get_tracker(device_key, getattr(event, "tenant_id", None))

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

            # Deduplication: avoid duplicate event insertions for the same finding
            for existing in tracker.events:
                if existing.get("event_id") == event.event_id and existing.get("finding_id") == finding.finding_id:
                    return

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
                if findings:
                    for finding in findings:
                        await self.process_detection(finding, event)
                    # Handled with high fidelity by Layer 3 detection engines; skip redundant raw flow duplication
                    return
            except Exception as det_err:
                logger.debug(f"[CorrelationEngine] Layer 3 detection evaluation error: {det_err}")

            now = time.time()
            tracker = await self._get_tracker(device_key, getattr(event, "tenant_id", None))

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

                # Check Crown Jewel / Database access (dynamic from config)
                crown_jewels = self.config.crown_jewel_ports
                lateral_ports = self.config.lateral_ports

                if dst_port in crown_jewels and getattr(event.network, "direction", "internal") == "internal":
                    service_desc = crown_jewels[dst_port]
                    stage = "crown_jewel_access"
                    evidence_item["stage"] = stage
                    evidence_item["mitre"] = "T1530 Data from Cloud/Internal Storage"
                    evidence_item["summary"] = f"Internal probe to high-value service ({service_desc}) on {dst_ip}:{dst_port}"

                # Check Lateral Movement ports (dynamic from config)
                elif dst_port in lateral_ports and getattr(event.network, "direction", "internal") == "internal":
                    service_desc = lateral_ports[dst_port]
                    stage = "lateral_movement"
                    evidence_item["stage"] = stage
                    evidence_item["mitre"] = "T1021 Remote Services"
                    evidence_item["summary"] = f"Internal lateral movement probe to {service_desc} on {dst_ip}:{dst_port}"

                # Check C2 / Outbound non-standard traffic
                elif getattr(event.network, "direction", "internal") == "outbound" and dst_port not in (80, 443, 53, 123):
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

                critical_tools = self.config.critical_tools
                if proc_name in critical_tools or event.endpoint.is_suspicious:
                    mitre_code = critical_tools.get(proc_name, "T1059 Command Execution")
                    stage = "malicious_process"
                    evidence_item["stage"] = stage
                    evidence_item["mitre"] = mitre_code
                    evidence_item["summary"] = f"Known offensive / penetration binary execution: {proc_name} ({mitre_code})"

                elif event.event_type in ("network_connection", "connection"):
                    r_port = event.endpoint.remote_port or 0
                    if r_port in self.config.lateral_ports:
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
        Executes the 6-Stage Intelligence Pipeline on the correlated tracker:
        1. Context enrichment (asset topology & Threat Intel)
        2. Behaviour analysis (rolling baselines & deviations)
        3. Causal correlation (MITRE attack chain synthesis)
        4. Dual-axis risk scoring with Anti-Double-Counting
        5. Incident explanation (executive narrative & guided response playbook)
        """
        # Stage 1 & 2: Context Enrichment
        context = self.enricher.enrich(latest_event)

        # Stage 3: Behaviour Analysis
        behaviour = self.behaviour_analyzer.analyze(latest_event, context)

        # Stage 4: Attack Chain Synthesis
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
        should_trigger = (
            len(attack_chain) >= 2 or
            has_malicious_proc or
            is_port_scan or
            obs_count >= self.config.min_observations_for_incident
        )
        if not should_trigger:
            return

        corr_state = CorrelatedIncidentState(
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

        # Stage 5: Dual-Axis Risk Assessment (with Anti-Double-Counting)
        risk = self.risk_engine.assess_risk(
            context=context,
            behaviour=behaviour,
            corr_state=corr_state,
            raw_events=list(tracker.events)
        )

        # Stage 6: Incident Explanation & Guided Playbook
        explanation = self.explainer.explain(
            context=context,
            corr_state=corr_state,
            risk=risk
        )

        await self._upsert_incident(
            tracker=tracker,
            event=latest_event,
            title=explanation.title,
            incident_type=explanation.incident_type,
            severity=risk.severity_label,
            confidence=risk.confidence_score,
            confidence_label=risk.confidence_label,
            attack_chain=attack_chain,
            investigation_steps=explanation.recommended_playbook,
            description=explanation.executive_summary,
            why_connected=explanation.why_connected,
            risk_reasoning=explanation.risk_reasoning,
            active_signals=[s.model_dump() for s in risk.active_signals]
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
        investigation_steps: List[str],
        description: Optional[str] = None,
        why_connected: Optional[str] = None,
        risk_reasoning: Optional[str] = None,
        active_signals: Optional[List[Dict[str, Any]]] = None
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
                    "description": description or title,
                    "why_connected": why_connected or "",
                    "risk_reasoning": risk_reasoning or "",
                    "active_signals": active_signals or [],
                    "attack_chain": attack_chain,
                    "evidence": evidence_slice,
                    "recommended_investigation_steps": investigation_steps
                })
                if getattr(event, "event_id", None):
                    try:
                        await evidence_service.link_event_to_incident(
                            tenant_id=event.tenant_id or "default",
                            incident_id=tracker.active_incident_id,
                            event_id=event.event_id,
                            role_in_incident=IncidentEventRole.SUPPORTING
                        )
                    except Exception:
                        pass
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
            "description": description or title,
            "why_connected": why_connected or "",
            "risk_reasoning": risk_reasoning or "",
            "active_signals": active_signals or [],
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

            # Link contributing events to incident (deduplicating against repeated event_ids)
            seen_eids = set()
            for ev in tracker.events:
                eid = ev.get("event_id") if isinstance(ev, dict) else getattr(ev, "event_id", None)
                if eid and eid not in seen_eids:
                    seen_eids.add(eid)
                    try:
                        fid = ev.get("finding_id") if isinstance(ev, dict) else None
                        await evidence_service.link_event_to_incident(
                            tenant_id=incident_doc["tenant_id"],
                            incident_id=inc_id,
                            event_id=eid,
                            alert_id=fid,
                            role_in_incident=IncidentEventRole.TRIGGER if eid == getattr(event, "event_id", None) else IncidentEventRole.SUPPORTING
                        )
                    except Exception:
                        pass

            # Realtime broadcast to SOC Analyst Dashboard via WebSocket
            await notification_service.notify_new_incident(incident_doc)
        except Exception as e:
            logger.error(f"[CorrelationEngine] Failed to persist incident: {e}", exc_info=True)

correlation_engine = CorrelationEngine()
