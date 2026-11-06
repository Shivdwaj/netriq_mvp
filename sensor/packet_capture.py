import time
import collections
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

@dataclass
class CapturedPacketSlice:
    """Local packet capture slice stored in sensor memory/disk, not sent to cloud."""
    packet_id: str
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_len: int
    raw_payload_snippet: bytes
    flow_id: str

class LocalPcapBuffer:
    """
    Local PCAP Ring Buffer.
    Keeps raw packet capture locally on the sensor host.
    Prevents mass exfiltration of raw packet payloads to the central cloud platform,
    conserving WAN bandwidth and preserving data privacy.
    Provides selective authorized extraction when an incident investigation requires deep packet inspection.
    """
    def __init__(self, max_mb: int = 256, retention_seconds: float = 3600.0):
        self.max_bytes = max_mb * 1024 * 1024
        self.retention_seconds = retention_seconds
        self._buffer: collections.deque[CapturedPacketSlice] = collections.deque()
        self._current_bytes = 0
        self._flow_index: Dict[str, List[CapturedPacketSlice]] = collections.defaultdict(list)

    def record_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        raw_payload: bytes = b"",
        packet_len: int = 64
    ) -> str:
        """Stores a packet slice in the local rolling buffer."""
        now = time.time()
        flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}"
        pkt_id = f"pkt-{int(now * 1000)}-{len(self._buffer) + 1}"

        slice_obj = CapturedPacketSlice(
            packet_id=pkt_id,
            timestamp=now,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_len=packet_len,
            raw_payload_snippet=raw_payload[:128], # Snip payload header
            flow_id=flow_id
        )

        slice_size = len(slice_obj.raw_payload_snippet) + 100
        self._buffer.append(slice_obj)
        self._flow_index[flow_id].append(slice_obj)
        self._current_bytes += slice_size

        self.prune()
        return pkt_id

    def prune(self):
        """Discards packet slices exceeding memory limits or retention window."""
        now = time.time()
        cutoff = now - self.retention_seconds

        while self._buffer and (self._buffer[0].timestamp < cutoff or self._current_bytes > self.max_bytes):
            old = self._buffer.popleft()
            self._current_bytes -= (len(old.raw_payload_snippet) + 100)
            if old.flow_id in self._flow_index:
                try:
                    self._flow_index[old.flow_id].remove(old)
                    if not self._flow_index[old.flow_id]:
                        del self._flow_index[old.flow_id]
                except ValueError:
                    pass

    def extract_selective_pcap(
        self,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        flow_id: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        time_range: Optional[tuple[float, float]] = None,
        max_packets: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Selective PCAP retrieval authorized for a specific investigation.
        Only called when an analyst explicitly requests supporting packets.
        """
        results = []
        for pkt in self._buffer:
            if src_ip and pkt.src_ip != src_ip:
                continue
            if dst_ip and pkt.dst_ip != dst_ip:
                continue
            if flow_id and pkt.flow_id != flow_id:
                continue
            if start_time is not None and pkt.timestamp < start_time:
                continue
            if end_time is not None and pkt.timestamp > end_time:
                continue
            if time_range:
                start, end = time_range
                if not (start <= pkt.timestamp <= end):
                    continue
            results.append({
                "packet_id": pkt.packet_id,
                "timestamp": pkt.timestamp,
                "src_ip": pkt.src_ip,
                "dst_ip": pkt.dst_ip,
                "src_port": pkt.src_port,
                "dst_port": pkt.dst_port,
                "protocol": pkt.protocol,
                "length": pkt.packet_len,
                "payload_hex": pkt.raw_payload_snippet.hex(),
                "hex_preview": pkt.raw_payload_snippet.hex()[:32]
            })
            if len(results) >= max_packets:
                break
        return results

    @property
    def total_buffered_packets(self) -> int:
        return len(self._buffer)
