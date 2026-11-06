"""
backend/intelligence/pipeline.py
The Unified NetrIQ Structured Intelligence Pipeline.

Orchestrates the 6 stages of genuine intelligence:
1. Event Interpretation: Extract subject, target, and semantic intent.
2. Context Enrichment: Asset criticality, protocol semantics, and Threat Intelligence.
3. Behaviour Analysis: Adaptive rolling baselines, first-seen tracking, and deviation scoring.
4. Causal Correlation: Sliding window event linking and MITRE ATT&CK attack chain synthesis.
5. Risk Assessment: Independent Severity & Confidence scoring with Anti-Double-Counting.
6. Incident Explanation: Executive narrative, causal reasoning, and guided response playbook.

Zero hardcoded numbers: fully configurable via IntelligenceConfig.
"""

from typing import Dict, Any, List, Optional, Set
from pydantic import BaseModel, Field

from backend.pipeline.schemas import NormalizedSecurityEvent
from backend.intelligence.config import IntelligenceConfig, intelligence_config
from backend.intelligence.enricher import ContextEnricher, EnrichedEventContext, threat_intel_feed
from backend.intelligence.behaviour import BehaviourAnalyzer, BehaviourAssessment
from backend.intelligence.correlator import RuleBasedCorrelator, DeviceActivityTracker, CorrelatedIncidentState
from backend.intelligence.risk_engine import RiskEngine, RiskAssessmentResult
from backend.intelligence.explainer import IncidentExplainer, IncidentExplanation
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class PipelineProcessingResult(BaseModel):
    """Complete output of the 6-stage structured intelligence pipeline."""
    event_id: str
    context: EnrichedEventContext
    behaviour: BehaviourAssessment
    correlation_state: CorrelatedIncidentState
    risk: Optional[RiskAssessmentResult] = None
    explanation: Optional[IncidentExplanation] = None
    should_synthesize_incident: bool = False


class StructuredIntelligencePipeline:
    """
    Executes the 6-Stage NetrIQ Intelligence Pipeline end-to-end.
    """

    def __init__(self, config: Optional[IntelligenceConfig] = None):
        self.config = config or intelligence_config
        self.enricher = ContextEnricher(self.config, threat_intel_feed)
        self.behaviour_analyzer = BehaviourAnalyzer(self.config)
        self.correlator = RuleBasedCorrelator(self.config)
        self.risk_engine = RiskEngine(self.config)
        self.explainer = IncidentExplainer()

    def process_event(
        self,
        event: NormalizedSecurityEvent,
        custom_crown_jewels: Optional[Set[str]] = None,
        raw_evidence: Optional[Dict[str, Any]] = None
    ) -> PipelineProcessingResult:
        """
        Processes a single security event through the complete 6-stage intelligence pipeline.
        """
        # --- Stage 1 & 2: Event Interpretation & Context Enrichment ---
        context = self.enricher.enrich(event, custom_crown_jewels)

        # --- Stage 3: Behaviour Analysis ---
        behaviour = self.behaviour_analyzer.analyze(event, context)

        # --- Stage 4: Causal Correlation ---
        tracker_key = context.subject_ip or "unknown"
        tracker = self.correlator.get_tracker(tracker_key)
        corr_state = self.correlator.record_observation(
            tracker=tracker,
            context=context,
            behaviour=behaviour,
            evidence_dict=raw_evidence
        )

        # If threshold for incident synthesis is met, execute Stage 5 & 6
        risk = None
        explanation = None
        if corr_state.should_synthesize_incident:
            # --- Stage 5: Dual-Axis Risk Assessment (Anti-Double-Counting) ---
            risk = self.risk_engine.assess_risk(
                context=context,
                behaviour=behaviour,
                corr_state=corr_state,
                raw_events=list(tracker.events)
            )

            # --- Stage 6: Incident Explanation ---
            explanation = self.explainer.explain(
                context=context,
                corr_state=corr_state,
                risk=risk
            )

        return PipelineProcessingResult(
            event_id=event.event_id,
            context=context,
            behaviour=behaviour,
            correlation_state=corr_state,
            risk=risk,
            explanation=explanation,
            should_synthesize_incident=corr_state.should_synthesize_incident
        )


# Global singleton pipeline instance
intelligence_pipeline = StructuredIntelligencePipeline()
