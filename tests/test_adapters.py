import sys
from pathlib import Path

# Add project root to path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from backend.adapters import suricata_adapter, zeek_adapter
from backend.pipeline.schemas import NormalizedSecurityEvent

def test_component_b_adapters():
    # 1. Exact user-provided illustrative Suricata payload
    suri_raw = {
        "event_type": "alert",
        "src_ip": "192.168.1.10",
        "dest_ip": "192.168.1.20",
        "proto": "TCP",
        "alert": {
            "signature": "Example detection",
            "severity": 2
        }
    }

    # 2. Exact user-provided illustrative Zeek payload
    zeek_raw = {
        "ts": 1793800000,
        "uid": "C123example",
        "id.orig_h": "192.168.1.10",
        "id.resp_h": "192.168.1.20",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl"
    }

    # Transform via Component B Adapters
    suri_event: NormalizedSecurityEvent = suricata_adapter.transform(suri_raw)
    zeek_event: NormalizedSecurityEvent = zeek_adapter.transform(zeek_raw)

    assert suri_event is not None, "SuricataAdapter failed to transform"
    assert zeek_event is not None, "ZeekAdapter failed to transform"

    print("=" * 70)
    print("  NETRIQ COMMON EVENT FORMAT (NCEF) ADAPTER VERIFICATION")
    print("=" * 70)

    print("\n[1] Suricata Adapter -> NetrIQ Standard Event:")
    print("  event_id          :", suri_event.event_id)
    print("  tenant_id         :", suri_event.tenant_id)
    print("  sensor_id         :", suri_event.sensor_id)
    print("  timestamp (UTC)   :", suri_event.timestamp)
    print("  ingestion_time    :", suri_event.ingestion_time)
    print("  source_ip         :", suri_event.source_ip)
    print("  destination_ip    :", suri_event.destination_ip)
    print("  source_port       :", suri_event.source_port)
    print("  destination_port  :", suri_event.destination_port)
    print("  protocol          :", suri_event.protocol)
    print("  event_type        :", suri_event.event_type)
    print("  detection_source  :", suri_event.detection_source)
    print("  severity          :", suri_event.severity)
    print("  direction         :", suri_event.direction)
    print("  network_interface :", suri_event.network_interface)
    print("  event_version     :", suri_event.event_version)
    print("  evidence          :", suri_event.evidence)

    print("\n[2] Zeek Adapter -> NetrIQ Standard Event:")
    print("  event_id          :", zeek_event.event_id)
    print("  tenant_id         :", zeek_event.tenant_id)
    print("  sensor_id         :", zeek_event.sensor_id)
    print("  timestamp (UTC)   :", zeek_event.timestamp)
    print("  ingestion_time    :", zeek_event.ingestion_time)
    print("  source_ip         :", zeek_event.source_ip)
    print("  destination_ip    :", zeek_event.destination_ip)
    print("  source_port       :", zeek_event.source_port)
    print("  destination_port  :", zeek_event.destination_port)
    print("  protocol          :", zeek_event.protocol)
    print("  event_type        :", zeek_event.event_type)
    print("  detection_source  :", zeek_event.detection_source)
    print("  severity          :", zeek_event.severity)
    print("  flow_id           :", zeek_event.flow_id)
    print("  rule_id           :", zeek_event.rule_id)
    print("  direction         :", zeek_event.direction)
    print("  network_interface :", zeek_event.network_interface)
    print("  evidence          :", zeek_event.evidence)

    # Core Assertions: Primary Standard Fields
    assert suri_event.source_ip == zeek_event.source_ip == "192.168.1.10"
    assert suri_event.destination_ip == zeek_event.destination_ip == "192.168.1.20"
    assert suri_event.protocol == zeek_event.protocol == "TCP"
    assert suri_event.tenant_id == zeek_event.tenant_id == "default"
    assert suri_event.event_version == zeek_event.event_version == "1.0.0"

    # Engine specific checks
    assert suri_event.detection_source == "suricata"
    assert suri_event.event_type == "alert"
    assert suri_event.evidence.get("signature") == "Example detection"

    assert zeek_event.detection_source == "zeek"
    assert zeek_event.event_type == "connection"
    assert zeek_event.destination_port == 443
    assert zeek_event.flow_id == "C123example"

    # UTC format check
    assert "T" in suri_event.timestamp and suri_event.timestamp.endswith("Z")
    assert "T" in zeek_event.timestamp and zeek_event.timestamp.endswith("Z")

    print("\n" + "=" * 70)
    print("ALL ASSERTIONS PASSED: Full NetrIQ Common Event Format (NCEF) verified!")
    print("=" * 70)

if __name__ == "__main__":
    test_component_b_adapters()
