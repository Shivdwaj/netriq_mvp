import asyncio
from typing import List, Optional

from backend.detection.models import DetectionFinding
from backend.detection.signature_engine import signature_engine, SignatureEngine
from backend.detection.rule_engine import rule_engine, RuleEngine
from backend.detection.behaviour_engine import behaviour_engine, BehaviourEngine
from backend.pipeline.schemas import NormalizedSecurityEvent
from backend.utils.logger import get_logger

logger = get_logger(__name__)

class DetectionManager:
    """
    NetrIQ Layer 3 Detection Engine Coordinator.
    Coordinates the three specialized detection engines:
    1. Signature Engine (Suricata alerts & known patterns)
    2. Rule Engine (NetrIQ-specific stateful rules: bursts, scans, DNS anomalies, failed connections)
    3. Behaviour Analysis Engine (Statistical baselines, z-score volume outliers, novel ports)

    Feeds high-fidelity DetectionFindings into Layer 4 Security Intelligence (CorrelationEngine).
    """

    def __init__(
        self,
        sig_engine: Optional[SignatureEngine] = None,
        rl_engine: Optional[RuleEngine] = None,
        beh_engine: Optional[BehaviourEngine] = None
    ):
        self.signature_engine = sig_engine or signature_engine
        self.rule_engine = rl_engine or rule_engine
        self.behaviour_engine = beh_engine or behaviour_engine

    @property
    def is_safe_detection_mode_active(self) -> bool:
        """
        Returns True if ML is isolated/disabled due to an integrity violation,
        with deterministic signature, rule, and behaviour engines actively protecting the network.
        """
        try:
            from backend.self_defense.intelligence_guard import intelligence_guard
            return intelligence_guard.is_safe_mode_active()
        except Exception:
            return False

    def evaluate(self, event: NormalizedSecurityEvent) -> List[DetectionFinding]:
        """
        Synchronously passes an event across all three detection engines,
        returning a combined list of DetectionFindings.
        """
        findings: List[DetectionFinding] = []

        # 1. Signature Engine (Suricata CVEs & Rules)
        try:
            sig_findings = self.signature_engine.analyze(event)
            if sig_findings:
                findings.extend(sig_findings)
        except Exception as e:
            logger.error(f"[DetectionManager] SignatureEngine error on event {event.event_id}: {e}", exc_info=True)

        # 2. Rule Engine (Stateful sliding-window rules)
        try:
            rule_findings = self.rule_engine.analyze(event)
            if rule_findings:
                findings.extend(rule_findings)
        except Exception as e:
            logger.error(f"[DetectionManager] RuleEngine error on event {event.event_id}: {e}", exc_info=True)

        # 3. Behaviour Analysis Engine (Statistical baselines & novel ports)
        try:
            beh_findings = self.behaviour_engine.analyze(event)
            if beh_findings:
                findings.extend(beh_findings)
        except Exception as e:
            logger.error(f"[DetectionManager] BehaviourEngine error on event {event.event_id}: {e}", exc_info=True)

        return findings

    async def process_event(self, event: NormalizedSecurityEvent):
        """
        Asynchronous pipeline processor subscribed to the SecurityEventBus.
        Evaluates the event and forwards any generated findings to the CorrelationEngine.
        """
        try:
            findings = self.evaluate(event)
            if findings:
                from backend.services.correlation_service import correlation_engine
                for finding in findings:
                    await correlation_engine.process_detection(finding, event)
        except Exception as e:
            logger.error(f"[DetectionManager] Error in process_event pipeline: {e}", exc_info=True)

detection_manager = DetectionManager()
