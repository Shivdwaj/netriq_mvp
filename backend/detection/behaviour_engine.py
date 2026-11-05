import time
import math
import collections
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field

from backend.detection.models import DetectionFinding, DetectionEngineType
from backend.pipeline.schemas import NormalizedSecurityEvent
from backend.utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class RunningStats:
    """
    Numerically stable running mean and standard deviation via Welford's algorithm.
    """
    count: int = 0
    mean: float = 0.0
    M2: float = 0.0

    def update(self, x: float):
        self.count += 1
        delta = x - self.mean
        self.mean += delta / self.count
        delta2 = x - self.mean
        self.M2 += delta * delta2

    @property
    def variance(self) -> float:
        return self.M2 / (self.count - 1) if self.count > 1 else 0.0

    @property
    def std_dev(self) -> float:
        return math.sqrt(self.variance)

    def z_score(self, x: float, min_std: float = 1.0) -> float:
        std = max(self.std_dev, min_std)
        return (x - self.mean) / std

@dataclass
class HostBehaviorProfile:
    """
    Behavioral baseline profile for a single host.
    Maintains running statistical baselines for egress bytes, connection rates,
    historical destination ports, and feature samples for future ML training.
    """
    source_ip: str
    min_learning_samples: int = 15
    total_observations: int = 0
    egress_bytes_stats: RunningStats = field(default_factory=RunningStats)
    conn_rate_stats: RunningStats = field(default_factory=RunningStats)
    known_dst_ports: Set[int] = field(default_factory=set)
    recent_connection_times: collections.deque = field(default_factory=collections.deque)
    last_egress_alert: float = 0.0
    last_novel_port_alert: float = 0.0
    feature_samples_for_ml: collections.deque = field(default_factory=lambda: collections.deque(maxlen=500))

    @property
    def is_baseline_ready(self) -> bool:
        return self.total_observations >= self.min_learning_samples

class BehaviourEngine:
    """
    Engine 3: Behaviour Analysis Engine
    Learns normal network behaviour and identifies unusual deviations.
    Initially implements statistical baselines (Welford running mean/variance, z-scores)
    and simple anomaly scoring. Collects representative telemetry for future ML training.
    """

    def __init__(
        self,
        min_learning_samples: int = 15,
        z_score_threshold: float = 3.0,
        min_anomalous_bytes: int = 50000, # 50 KB minimum for volume anomaly
        alert_cooldown_seconds: float = 60.0
    ):
        self.min_learning_samples = min_learning_samples
        self.z_score_threshold = z_score_threshold
        self.min_anomalous_bytes = min_anomalous_bytes
        self.alert_cooldown_seconds = alert_cooldown_seconds
        self._profiles: Dict[str, HostBehaviorProfile] = {}

    def _get_profile(self, source_ip: str) -> HostBehaviorProfile:
        if source_ip not in self._profiles:
            self._profiles[source_ip] = HostBehaviorProfile(
                source_ip=source_ip,
                min_learning_samples=self.min_learning_samples
            )
        return self._profiles[source_ip]

    def _extract_ml_feature_vector(self, event: NormalizedSecurityEvent, bytes_val: int) -> Dict[str, Any]:
        """Extracts normalized feature vector for future representative ML model training."""
        return {
            "timestamp": event.timestamp,
            "source_ip": event.source_ip,
            "bytes": bytes_val,
            "destination_port": event.destination_port or 0,
            "direction": event.direction or "internal",
            "protocol": event.protocol or "TCP"
        }

    def analyze(self, event: NormalizedSecurityEvent) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []
        src_ip = event.source_ip
        if not src_ip or src_ip in ("127.0.0.1", "0.0.0.0", "unknown"):
            return findings

        profile = self._get_profile(src_ip)
        profile.total_observations += 1
        now = time.time()

        # Extract bytes from evidence or event
        raw_bytes = int(
            event.evidence.get("orig_bytes") or
            event.evidence.get("byte_count") or
            event.evidence.get("length") or
            0
        )
        dst_port = event.destination_port or 0
        is_outbound = event.direction == "outbound" or event.network.direction == "outbound"

        # Record feature sample for future ML dataset
        profile.feature_samples_for_ml.append(self._extract_ml_feature_vector(event, raw_bytes))

        # --- 1. Egress Volume Anomaly Detection (Statistical Z-Score) ---
        if is_outbound and raw_bytes > 0:
            if profile.is_baseline_ready:
                z = profile.egress_bytes_stats.z_score(float(raw_bytes), min_std=1000.0)
                if z >= self.z_score_threshold and raw_bytes >= self.min_anomalous_bytes:
                    if now - profile.last_egress_alert > self.alert_cooldown_seconds:
                        profile.last_egress_alert = now
                        anomaly_score = min(1.0, round(z / 6.0, 2))
                        findings.append(DetectionFinding(
                            engine_type=DetectionEngineType.BEHAVIOUR,
                            rule_id="NETRIQ:BEHAVIOUR:ANOMALOUS_EGRESS_VOLUME",
                            title="Statistical Egress Volume Anomaly Detected",
                            description=(
                                f"Host {src_ip} transferred {raw_bytes:,} bytes outbound to {event.destination_ip}:{dst_port}, "
                                f"which is {z:.1f} standard deviations above baseline (Mean: {profile.egress_bytes_stats.mean:,.0f} bytes, "
                                f"StdDev: {profile.egress_bytes_stats.std_dev:,.0f})."
                            ),
                            severity="HIGH" if z >= 4.5 else "MEDIUM",
                            confidence=max(0.75, min(0.95, anomaly_score)),
                            mitre_technique="T1048 Exfiltration Over Alternative Protocol",
                            mitre_stage="c2_exfil",
                            source_ip=src_ip,
                            destination_ip=event.destination_ip,
                            source_port=event.source_port,
                            destination_port=dst_port,
                            protocol=event.protocol,
                            timestamp=event.timestamp,
                            evidence={
                                "observed_bytes": raw_bytes,
                                "baseline_mean_bytes": round(profile.egress_bytes_stats.mean, 1),
                                "baseline_std_dev": round(profile.egress_bytes_stats.std_dev, 1),
                                "z_score": round(z, 2),
                                "anomaly_score": anomaly_score,
                                "training_samples": profile.egress_bytes_stats.count
                            },
                            matched_event_ids=[event.event_id]
                        ))
            # Continuously update statistical baseline
            profile.egress_bytes_stats.update(float(raw_bytes))

        # --- 2. Novel Destination Port Deviation ---
        # Known high-risk novel ports commonly used by implants / reverse shells
        HIGH_RISK_PORTS = {4444, 8443, 9001, 1337, 6667, 31337, 5555, 8088}
        if dst_port > 0:
            if profile.is_baseline_ready:
                if dst_port not in profile.known_dst_ports and (dst_port in HIGH_RISK_PORTS or dst_port > 1024):
                    if now - profile.last_novel_port_alert > self.alert_cooldown_seconds:
                        profile.last_novel_port_alert = now
                        is_dangerous = dst_port in HIGH_RISK_PORTS
                        findings.append(DetectionFinding(
                            engine_type=DetectionEngineType.BEHAVIOUR,
                            rule_id="NETRIQ:BEHAVIOUR:NOVEL_PORT_COMMUNICATION",
                            title="Unusual / Novel Destination Port Activity",
                            description=(
                                f"Host {src_ip} initiated communication to port {dst_port} on {event.destination_ip}, "
                                f"a port never observed during the baseline learning period ({len(profile.known_dst_ports)} known ports)."
                            ),
                            severity="HIGH" if is_dangerous else "MEDIUM",
                            confidence=0.86 if is_dangerous else 0.72,
                            mitre_technique="T1571 Non-Standard Port" if is_dangerous else "T1046 Network Service Discovery",
                            mitre_stage="c2_exfil" if is_dangerous else "discovery",
                            source_ip=src_ip,
                            destination_ip=event.destination_ip,
                            source_port=event.source_port,
                            destination_port=dst_port,
                            protocol=event.protocol,
                            timestamp=event.timestamp,
                            evidence={
                                "novel_port": dst_port,
                                "known_ports_count": len(profile.known_dst_ports),
                                "sample_known_ports": sorted(list(profile.known_dst_ports))[:15],
                                "is_high_risk_signature_port": is_dangerous
                            },
                            matched_event_ids=[event.event_id]
                        ))

            # Record port into profile baseline
            profile.known_dst_ports.add(dst_port)

        return findings

behaviour_engine = BehaviourEngine()
