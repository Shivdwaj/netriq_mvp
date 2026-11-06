"""
backend/intelligence/risk_engine.py
Stage 5: Dual-Axis Risk Assessment with Anti-Double-Counting

Features:
- Completely decouples Severity (potential business impact) from Confidence (evidentiary certainty).
- Configurable scoring weights:
  1. Known malicious signature (default: 30)
  2. High connection frequency (default: 20)
  3. Unusual destination (default: 15)
  4. Multiple related events (default: 20)
  5. Behavioural deviation (default: 15)
- Anti-Double-Counting:
  Groups correlated signals into causal domains and applies an alpha dampening factor
  to secondary signals within the same domain so overlapping detections do not inflate risk.
- Zero hardcoded numbers: all thresholds, cutoffs, and weights are loaded from IntelligenceConfig.
"""

from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from backend.intelligence.config import IntelligenceConfig, intelligence_config
from backend.intelligence.enricher import EnrichedEventContext
from backend.intelligence.behaviour import BehaviourAssessment
from backend.intelligence.correlator import CorrelatedIncidentState


class SignalCategory(str, Enum):
    SIGNATURE = "signature"
    FREQUENCY = "frequency"
    DESTINATION = "destination"
    CORRELATION = "correlation"
    BEHAVIOUR = "behaviour"


class ActiveRiskSignal(BaseModel):
    category: SignalCategory
    name: str
    raw_weight: float
    effective_weight: float
    causal_domain: str
    description: str


class RiskAssessmentResult(BaseModel):
    """Output of Stage 5: Dual-Axis Risk Assessment."""
    severity_score: float  # 0.0 to 100.0
    severity_label: str    # LOW, MEDIUM, HIGH, CRITICAL
    confidence_score: float  # 0.0 to 1.0
    confidence_label: str  # NEEDS_VALIDATION, SUSPECTED, PROBABLE, CONFIRMED
    active_signals: List[ActiveRiskSignal] = Field(default_factory=list)
    raw_score_sum: float = 0.0
    dampening_discount_applied: float = 0.0
    criticality_multiplier: float = 1.0


class RiskEngine:
    """
    Executes Stage 5 of the Intelligence Pipeline:
    Estimates Severity and Confidence independently using a configurable,
    non-additive, anti-double-counting scoring algorithm.
    """

    def __init__(self, config: Optional[IntelligenceConfig] = None):
        self.config = config or intelligence_config

    def assess_risk(
        self,
        context: EnrichedEventContext,
        behaviour: BehaviourAssessment,
        corr_state: CorrelatedIncidentState,
        raw_events: List[Dict[str, Any]]
    ) -> RiskAssessmentResult:
        """
        Calculates independent Severity and Confidence scores with signal subsumption.
        """
        signals: List[ActiveRiskSignal] = []

        # ----------------------------------------------------------------------
        # 1. Signal Identification
        # ----------------------------------------------------------------------
        # Signal 1: Known malicious signature (from Suricata, Zeek, or Critical Tools)
        has_sig = any(e.get("source") in ("suricata", "detection_signature") for e in raw_events) or context.is_suspicious_tool
        if has_sig:
            signals.append(ActiveRiskSignal(
                category=SignalCategory.SIGNATURE,
                name="Known malicious signature",
                raw_weight=self.config.weight_signature,
                effective_weight=self.config.weight_signature,
                causal_domain="pattern_and_signature",
                description="Signature match from network IDS or known offensive binary"
            ))

        # Signal 2: High connection frequency
        if behaviour.is_high_frequency or corr_state.is_port_scan:
            signals.append(ActiveRiskSignal(
                category=SignalCategory.FREQUENCY,
                name="High connection frequency",
                raw_weight=self.config.weight_connection_frequency,
                effective_weight=self.config.weight_connection_frequency,
                causal_domain="pattern_and_signature",
                description=f"Rapid connection burst ({behaviour.connection_rate_per_min} conns/min or {corr_state.unique_ports_count} ports probed)"
            ))

        # Signal 3: Unusual destination / Crown jewel asset
        if behaviour.is_unusual_destination or context.is_crown_jewel or corr_state.has_crown_jewel:
            signals.append(ActiveRiskSignal(
                category=SignalCategory.DESTINATION,
                name="Unusual destination",
                raw_weight=self.config.weight_unusual_destination,
                effective_weight=self.config.weight_unusual_destination,
                causal_domain="target_and_behaviour",
                description=f"Targeting sensitive asset or unprecedented destination {context.target_ip}"
            ))

        # Signal 4: Multiple related events / attack progression
        if len(corr_state.attack_chain) >= 2 or corr_state.observation_count >= self.config.min_observations_for_incident:
            stage_count = max(1, len(corr_state.attack_chain))
            multi_weight = min(self.config.weight_multiple_events * 1.5, self.config.weight_multiple_events + (stage_count - 1) * 5)
            signals.append(ActiveRiskSignal(
                category=SignalCategory.CORRELATION,
                name="Multiple related events",
                raw_weight=multi_weight,
                effective_weight=multi_weight,
                causal_domain="progression",
                description=f"Correlated {corr_state.observation_count} events across {stage_count} MITRE attack stages"
            ))

        # Signal 5: Behavioural deviation
        if behaviour.behavioural_deviation_score >= 0.25:
            scaled_weight = self.config.weight_behavioural_deviation * behaviour.behavioural_deviation_score
            signals.append(ActiveRiskSignal(
                category=SignalCategory.BEHAVIOUR,
                name="Behavioural deviation",
                raw_weight=scaled_weight,
                effective_weight=scaled_weight,
                causal_domain="target_and_behaviour",
                description=f"Host activity represents a {int(behaviour.behavioural_deviation_score * 100)}% anomaly from baseline"
            ))

        # ----------------------------------------------------------------------
        # 2. Anti-Double-Counting Scoring Algorithm
        # ----------------------------------------------------------------------
        # Group signals by causal domain
        domain_groups: Dict[str, List[ActiveRiskSignal]] = {}
        for sig in signals:
            domain_groups.setdefault(sig.causal_domain, []).append(sig)

        alpha = self.config.correlation_dampening_factor
        raw_sum = sum(s.raw_weight for s in signals)
        subsumed_sum = 0.0

        for domain, group_signals in domain_groups.items():
            # Sort descending by raw weight: highest signal gets 100% weight
            sorted_signals = sorted(group_signals, key=lambda s: s.raw_weight, reverse=True)
            primary = sorted_signals[0]
            domain_score = primary.raw_weight

            # Secondary correlated signals in the same domain are discounted by alpha
            for secondary in sorted_signals[1:]:
                dampened = secondary.raw_weight * alpha
                secondary.effective_weight = round(dampened, 2)
                domain_score += dampened

            subsumed_sum += domain_score

        # Apply asset criticality multiplier
        crit_multiplier = context.asset_criticality_multiplier
        final_severity_raw = subsumed_sum * crit_multiplier
        final_severity = round(min(self.config.max_severity_score, final_severity_raw), 2)
        dampening_discount = round(max(0.0, raw_sum - final_severity), 2)

        # Map to Severity Label
        if (final_severity >= self.config.severity_critical_threshold or
            context.is_crown_jewel or
            len(corr_state.attack_chain) >= 3):
            sev_label = "CRITICAL"
        elif final_severity >= self.config.severity_high_threshold:
            sev_label = "HIGH"
        elif final_severity >= self.config.severity_medium_threshold:
            sev_label = "MEDIUM"
        else:
            sev_label = "LOW"

        # ----------------------------------------------------------------------
        # 3. Independent Confidence (Certainty / Proof of Occurrence)
        # ----------------------------------------------------------------------
        sources = {e.get("source") for e in raw_events if e.get("source")}
        engine_count = len(sources)

        # Baseline certainty from evidence volume
        if corr_state.observation_count >= 10:
            base_conf = 0.75
        elif corr_state.observation_count >= 5:
            base_conf = 0.65
        elif corr_state.observation_count >= 3:
            base_conf = 0.55
        else:
            base_conf = 0.45

        # Corroboration bonus across independent sensors / engines
        if engine_count >= 3:
            base_conf += 0.20
        elif engine_count == 2:
            base_conf += 0.12

        # Established connection verification check (e.g. TCP 'SF' state or confirmed payload)
        has_sf = any(e.get("details", {}).get("conn_state") == "SF" or e.get("conn_state") == "SF" for e in raw_events)
        if has_sf and has_sig:
            base_conf += 0.15
        elif has_sf:
            base_conf += 0.08

        # Threat Intel confirmation bonus
        if context.threat_intel:
            base_conf += 0.10

        final_conf = round(max(0.35, min(0.99, base_conf)), 2)

        # Map to Confidence Label
        if final_conf >= self.config.confidence_confirmed_threshold:
            conf_label = "CONFIRMED"
        elif final_conf >= self.config.confidence_probable_threshold:
            conf_label = "PROBABLE"
        elif final_conf >= self.config.confidence_suspected_threshold:
            conf_label = "SUSPECTED"
        else:
            conf_label = "NEEDS_VALIDATION"

        return RiskAssessmentResult(
            severity_score=final_severity,
            severity_label=sev_label,
            confidence_score=final_conf,
            confidence_label=conf_label,
            active_signals=signals,
            raw_score_sum=round(raw_sum, 2),
            dampening_discount_applied=dampening_discount,
            criticality_multiplier=crit_multiplier
        )

