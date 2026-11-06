"""
backend/intelligence
Structured Intelligence Pipeline for NetrIQ:
- Stage 1: Event Interpretation
- Stage 2: Context Enrichment & Threat Intelligence
- Stage 3: Behaviour Analysis & Adaptive Baselines
- Stage 4: Causal Correlation & MITRE ATT&CK Chain Tracking
- Stage 5: Dual-Axis Risk Assessment with Anti-Double-Counting
- Stage 6: Incident Explanation & Forensic Reasoning
"""

from backend.intelligence.config import IntelligenceConfig, intelligence_config
from backend.intelligence.enricher import ContextEnricher, EnrichedEventContext, ThreatIntelStore, threat_intel_feed
from backend.intelligence.behaviour import BehaviourAnalyzer, BehaviourAssessment
from backend.intelligence.correlator import RuleBasedCorrelator, DeviceActivityTracker, CorrelatedIncidentState
from backend.intelligence.risk_engine import RiskEngine, RiskAssessmentResult, SignalCategory, ActiveRiskSignal
from backend.intelligence.explainer import IncidentExplainer, IncidentExplanation
from backend.intelligence.pipeline import StructuredIntelligencePipeline, intelligence_pipeline, PipelineProcessingResult

__all__ = [
    "IntelligenceConfig",
    "intelligence_config",
    "ContextEnricher",
    "EnrichedEventContext",
    "ThreatIntelStore",
    "threat_intel_feed",
    "BehaviourAnalyzer",
    "BehaviourAssessment",
    "RuleBasedCorrelator",
    "DeviceActivityTracker",
    "CorrelatedIncidentState",
    "RiskEngine",
    "RiskAssessmentResult",
    "SignalCategory",
    "ActiveRiskSignal",
    "IncidentExplainer",
    "IncidentExplanation",
    "StructuredIntelligencePipeline",
    "intelligence_pipeline",
    "PipelineProcessingResult"
]
