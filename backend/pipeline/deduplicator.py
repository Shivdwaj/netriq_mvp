import time
import hashlib
from typing import Dict, Optional
from backend.pipeline.schemas import NormalizedSecurityEvent

class EventDeduplicator:
    """
    Sliding-window deduplication filter.
    Prevents duplicate network packet retransmissions or repetitive agent heartbeats
    from overwhelming downstream correlation and intelligence engines.
    """

    def __init__(self, window_seconds: float = 10.0, max_cache_size: int = 50000):
        self.window_seconds = window_seconds
        self.max_cache_size = max_cache_size
        self._seen_signatures: Dict[str, float] = {}

    def _generate_signature(self, event: NormalizedSecurityEvent) -> str:
        """
        Creates a compact hash signature based on event semantics:
        - Network: src_ip, dst_ip, dst_port, protocol
        - Endpoint process: device mac/ip, process_name, command_line
        - Endpoint connection: device mac/ip, remote_ip, remote_port, connection_state
        - Endpoint auth: device mac/ip, user, auth_status
        """
        parts = [event.event_type.value, event.source.value]

        if event.network:
            parts.extend([
                str(event.network.src_ip),
                str(event.network.dst_ip),
                str(event.network.dst_port),
                str(event.network.protocol)
            ])
        elif event.endpoint:
            parts.extend([
                str(event.device.mac or event.device.ip),
                str(event.endpoint.process_name or ""),
                str(event.endpoint.remote_ip or ""),
                str(event.endpoint.remote_port or ""),
                str(event.endpoint.connection_state or ""),
                str(event.endpoint.user or ""),
                str(event.endpoint.auth_status or "")
            ])
        else:
            parts.append(str(event.device.mac or event.device.ip))

        raw_str = "|".join(parts)
        return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

    def is_duplicate(self, event: NormalizedSecurityEvent) -> bool:
        """
        Checks if the event is a duplicate within the sliding time window.
        Returns True if duplicate (should be dropped), False if unique (should be processed).
        """
        now = time.time()
        sig = self._generate_signature(event)

        # Evict old entries if cache is growing too large
        if len(self._seen_signatures) > self.max_cache_size:
            self._cleanup_expired(now)

        last_seen = self._seen_signatures.get(sig)
        if last_seen is not None and (now - last_seen) < self.window_seconds:
            # Duplicate within time window
            return True

        self._seen_signatures[sig] = now
        return False

    def _cleanup_expired(self, current_time: float):
        cutoff = current_time - self.window_seconds
        keys_to_remove = [k for k, v in self._seen_signatures.items() if v < cutoff]
        for k in keys_to_remove:
            del self._seen_signatures[k]

deduplicator = EventDeduplicator()

