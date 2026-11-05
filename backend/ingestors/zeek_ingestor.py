import json
from typing import Optional, Dict, Any, List

from backend.utils.logger import get_logger
from backend.pipeline.schemas import NormalizedSecurityEvent
from backend.adapters.zeek_adapter import zeek_adapter

logger = get_logger(__name__)

class ZeekLogIngestor:
    """
    Parses Zeek connection and protocol logs (conn.log, dns.log, ssl.log).
    Delegates normalization directly to ZeekAdapter producing NetrIQ Common Event Format (NCEF).
    """

    def parse_conn_record(self, record: Dict[str, Any]) -> Optional[NormalizedSecurityEvent]:
        """Parses a single Zeek conn.log record."""
        return zeek_adapter.transform(record)

    def parse_dns_record(self, record: Dict[str, Any]) -> Optional[NormalizedSecurityEvent]:
        """Parses a single Zeek dns.log record."""
        return zeek_adapter.transform(record)

    def parse_log_line(self, line: str) -> Optional[NormalizedSecurityEvent]:
        """Parses a single JSON line string from Zeek JSON logs."""
        return zeek_adapter.transform(line)

zeek_ingestor = ZeekLogIngestor()
