import json
from typing import Optional, Dict, Any, List

from backend.utils.logger import get_logger
from backend.pipeline.schemas import NormalizedSecurityEvent
from backend.adapters.suricata_adapter import suricata_adapter

logger = get_logger(__name__)

class SuricataEveIngestor:
    """
    Parses Suricata EVE JSON (Extensible Event Format).
    Delegates normalization directly to SuricataAdapter producing NetrIQ Common Event Format (NCEF).
    """

    def parse_eve_record(self, record: Dict[str, Any]) -> Optional[NormalizedSecurityEvent]:
        """Converts a single decoded Suricata EVE record into a NormalizedSecurityEvent."""
        return suricata_adapter.transform(record)

    def parse_eve_line(self, line: str) -> Optional[NormalizedSecurityEvent]:
        """Parses a single JSON line string from eve.json."""
        return suricata_adapter.transform(line)

suricata_ingestor = SuricataEveIngestor()
