from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Union
from backend.pipeline.schemas import NormalizedSecurityEvent

class BaseEventAdapter(ABC):
    """
    Component B: Abstract Base Adapter for security telemetry engines.
    Converts vendor/engine-specific structured payloads into NetrIQ's NormalizedSecurityEvent.
    """

    @property
    @abstractmethod
    def engine_name(self) -> str:
        """Name of the telemetry engine (e.g., 'suricata', 'zeek')."""
        pass

    @abstractmethod
    def transform(self, raw_data: Union[str, Dict[str, Any]]) -> Optional[NormalizedSecurityEvent]:
        """
        Parses a single raw event (JSON string or dict) and returns a standard NetrIQ event.
        Returns None if the event is malformed or filtered.
        """
        pass

    def batch_transform(self, records: List[Union[str, Dict[str, Any]]]) -> List[NormalizedSecurityEvent]:
        """Batch transforms a list of raw records, filtering out None values."""
        results: List[NormalizedSecurityEvent] = []
        for rec in records:
            event = self.transform(rec)
            if event:
                results.append(event)
        return results
