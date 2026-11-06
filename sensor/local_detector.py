import time
import collections
from typing import Dict, Any, List, Optional
from backend.pipeline.schemas import NormalizedSecurityEvent

class LocalDetectionEngine:
    """
    Step 5: Local Detection Engine
    Evaluates connection patterns and heuristics locally at the sensor within configured sliding windows.
    Detects port scans, multi-host sweeps, and connection churn BEFORE sending to cloud.
    """
    def __init__(
        self,
        window_seconds: float = 60.0,
        port_scan_threshold: int = 8,
        host_sweep_threshold: int = 5
    ):
        self.window_seconds = window_seconds
        self.port_scan_threshold = port_scan_threshold
        self.host_sweep_threshold = host_sweep_threshold
        
        # Track connections per source IP: src_ip -> deque of (timestamp, dst_ip, dst_port)
        self._src_connections: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self._alerted_scans: Dict[str, float] = {}

    def evaluate(self, event: NormalizedSecurityEvent) -> Optional[Dict[str, Any]]:
        """
        Evaluates a normalized connection event against local detection rules.
        Returns a LocalDetectionAlert dictionary if a local rule triggers, or None.
        """
        src = event.source_ip
        dst = event.destination_ip
        dport = event.destination_port or 0
        now = time.time()

        if not src or src in ("127.0.0.1", "0.0.0.0"):
            return None

        dq = self._src_connections[src]
        dq.append((now, dst, dport))

        # Prune expired connections
        cutoff = now - self.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        # Unique destination ports and IPs in the current sliding window
        unique_ports = {p for _, _, p in dq if p > 0}
        unique_ips = {ip for _, ip, _ in dq if ip}

        # Rule 1: Multi-Port Reconnaissance Sweep (Port Scan Detection)
        if len(unique_ports) >= self.port_scan_threshold:
            last_alert = self._alerted_scans.get(src, 0.0)
            if (now - last_alert) > self.window_seconds:
                self._alerted_scans[src] = now
                
                # Upgrade event metadata
                event.event_type = "alert"
                event.severity = "MEDIUM"
                event.rule_id = "NETRIQ:RULE:PORT_SCAN_RECON"
                event.evidence["alert_name"] = "Multi-Port Reconnaissance Sweep"
                event.evidence["unique_ports_count"] = len(unique_ports)
                event.evidence["target_ip"] = dst
                event.evidence["confidence"] = 0.85
                event.evidence["probed_ports"] = sorted(list(unique_ports))[:20]

                return {
                    "rule_id": "NETRIQ:RULE:PORT_SCAN_RECON",
                    "title": "Local Sensor Detection: Multi-Port Reconnaissance Sweep",
                    "source_ip": src,
                    "target_ip": dst,
                    "unique_ports": len(unique_ports),
                    "window_seconds": self.window_seconds,
                    "confidence": 0.85
                }

        # Rule 2: Multi-Host Lateral Sweep
        if len(unique_ips) >= self.host_sweep_threshold:
            last_alert = self._alerted_scans.get(f"{src}_hosts", 0.0)
            if (now - last_alert) > self.window_seconds:
                self._alerted_scans[f"{src}_hosts"] = now
                event.event_type = "alert"
                event.severity = "HIGH"
                event.rule_id = "NETRIQ:RULE:MULTI_HOST_SWEEP"
                event.evidence["alert_name"] = "Multi-Host Lateral Sweep"
                event.evidence["unique_hosts_count"] = len(unique_ips)
                event.evidence["confidence"] = 0.88

                return {
                    "rule_id": "NETRIQ:RULE:MULTI_HOST_SWEEP",
                    "title": "Local Sensor Detection: Multi-Host Lateral Sweep",
                    "source_ip": src,
                    "unique_hosts": len(unique_ips),
                    "confidence": 0.88
                }

        return None
