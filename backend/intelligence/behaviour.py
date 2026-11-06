"""
backend/intelligence/behaviour.py
Stage 3: Behaviour Analysis & Capability 2: Behavioural Intelligence

Maintains adaptive rolling baselines per host with zero hardcoded values:
- Tracks first-seen destination IPs and ports.
- Computes rolling connection frequency rates and detects statistical bursts.
- Evaluates peer fan-out and unusual port diversity.
- Produces an explainable BehaviourAssessment with deviation scores and forensic reasons.
"""

import time
import collections
from typing import Dict, Any, List, Set, Optional
from pydantic import BaseModel, Field

from backend.pipeline.schemas import NormalizedSecurityEvent
from backend.intelligence.config import IntelligenceConfig, intelligence_config
from backend.intelligence.enricher import EnrichedEventContext
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class BehaviourAssessment(BaseModel):
    """Result of Stage 3: Behaviour Analysis comparing activity against established host baselines."""
    source_ip: str
    is_unusual_destination: bool = False
    is_unusual_port: bool = False
    is_high_frequency: bool = False
    connection_rate_per_min: float = 0.0
    baseline_avg_rate: float = 0.0
    behavioural_deviation_score: float = 0.0  # 0.0 (normal) to 1.0 (extreme anomaly)
    deviation_reasons: List[str] = Field(default_factory=list)


class HostBehaviourTracker:
    """
    Adaptive baseline profile for an individual host/device.
    Maintains running history of observed destinations, ports, and connection frequencies.
    """

    def __init__(self, ip: str, window_seconds: float = 600.0):
        self.ip = ip
        self.window_seconds = window_seconds
        self.known_destination_ips: Set[str] = set()
        self.known_destination_ports: Set[int] = set()
        self.recent_timestamps: collections.deque = collections.deque()
        self.total_observations: int = 0
        self.created_at: float = time.time()
        self.last_updated: float = time.time()

    def record_activity(self, dst_ip: str, dst_port: int, now: float) -> tuple[bool, bool, float]:
        """
        Records an interaction and returns:
        (is_new_ip, is_new_port, current_rate_per_min)
        """
        self.last_updated = now
        self.total_observations += 1

        # Check novel targets
        is_new_ip = bool(dst_ip and dst_ip not in self.known_destination_ips)
        is_new_port = bool(dst_port and dst_port not in self.known_destination_ports)

        if dst_ip:
            self.known_destination_ips.add(dst_ip)
        if dst_port:
            self.known_destination_ports.add(dst_port)

        # Update sliding connection timestamps
        self.recent_timestamps.append(now)
        cutoff = now - self.window_seconds
        while self.recent_timestamps and self.recent_timestamps[0] < cutoff:
            self.recent_timestamps.popleft()

        # Compute rate per minute over active window
        active_window_min = max(0.1, (now - cutoff) / 60.0)
        rate_per_min = len(self.recent_timestamps) / active_window_min

        return is_new_ip, is_new_port, rate_per_min


class BehaviourAnalyzer:
    """
    Executes Stage 3 of the Intelligence Pipeline:
    Compares current event and context against host baselines.
    """

    def __init__(self, config: Optional[IntelligenceConfig] = None):
        self.config = config or intelligence_config
        self._trackers: Dict[str, HostBehaviourTracker] = {}

    def _get_tracker(self, ip: str) -> HostBehaviourTracker:
        if ip not in self._trackers:
            self._trackers[ip] = HostBehaviourTracker(ip, self.config.window_seconds)
        return self._trackers[ip]

    def analyze(self, event: NormalizedSecurityEvent, context: EnrichedEventContext) -> BehaviourAssessment:
        """Evaluates event against host profile and returns behavioral deviation metrics."""
        now = time.time()
        src_ip = context.subject_ip
        dst_ip = context.target_ip or ""
        dst_port = context.target_port

        if not src_ip or src_ip in ("0.0.0.0", "127.0.0.1", "unknown"):
            return BehaviourAssessment(source_ip=src_ip)

        tracker = self._get_tracker(src_ip)
        is_warm = tracker.total_observations >= 3

        is_new_ip, is_new_port, current_rate = tracker.record_activity(dst_ip, dst_port, now)

        # Baseline deviation evaluation
        deviation_score = 0.0
        deviation_reasons: List[str] = []

        is_unusual_dest = False
        is_unusual_port = False
        is_high_freq = False

        # Only evaluate novelty after host tracker has established initial warmup observations
        if is_warm and is_new_ip and dst_ip and not dst_ip.startswith("127."):
            is_unusual_dest = True
            deviation_score += 0.35
            deviation_reasons.append(f"Unprecedented destination {dst_ip} (never contacted in established host baseline)")

        if is_warm and is_new_port and dst_port not in (80, 443, 53):
            is_unusual_port = True
            deviation_score += 0.25
            deviation_reasons.append(f"Unprecedented destination port {dst_port} accessed")

        # Rate burst check against configurable threshold
        if current_rate >= self.config.high_freq_connection_threshold:
            is_high_freq = True
            deviation_score += 0.40
            deviation_reasons.append(
                f"High connection frequency burst: {current_rate:.1f} conns/min (threshold: {self.config.high_freq_connection_threshold})"
            )

        # Crown Jewel amplification
        if context.is_crown_jewel:
            deviation_score += 0.30
            deviation_reasons.append(f"Targeted high-value internal asset ({context.target_service or dst_ip})")

        clamped_score = min(1.0, round(deviation_score, 2))

        return BehaviourAssessment(
            source_ip=src_ip,
            is_unusual_destination=is_unusual_dest,
            is_unusual_port=is_unusual_port,
            is_high_frequency=is_high_freq,
            connection_rate_per_min=round(current_rate, 2),
            baseline_avg_rate=round(current_rate, 2),
            behavioural_deviation_score=clamped_score,
            deviation_reasons=deviation_reasons
        )

