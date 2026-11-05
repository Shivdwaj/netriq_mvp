import sys
from pathlib import Path

# Add project root to path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from backend.adapters import SuricataAdapter, ZeekAdapter, suricata_adapter, zeek_adapter
from backend.pipeline.schemas import NormalizedSecurityEvent, EventSource

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
    suri_event = suricata_adapter.transform(suri_raw)
    zeek_event = zeek_adapter.transform(zeek_raw)

    assert suri_event is not None, "SuricataAdapter failed to transform"
    assert zeek_event is not None, "ZeekAdapter failed to transform"

    print("=" * 65)
    print("  COMPONENT B: ADAPTER TRANSFORMATION TEST")
    print("=" * 65)

    print("\n[1] Suricata Adapter Result (NetrIQ Standard Event):")
    print("  Engine Source :", suri_event.source.value)
    print("  Event Type    :", suri_event.event_type.value)
    print("  Src -> Dst    :", f"{suri_event.network.src_ip} -> {suri_event.network.dst_ip} ({suri_event.network.protocol})")
    print("  Signature     :", suri_event.raw_metadata.get("signature"))
    print("  Severity Level:", suri_event.raw_metadata.get("severity_level"))
    print("  Direction     :", suri_event.network.direction)

    print("\n[2] Zeek Adapter Result (NetrIQ Standard Event):")
    print("  Engine Source :", zeek_event.source.value)
    print("  Event Type    :", zeek_event.event_type.value)
    print("  Src -> Dst    :", f"{zeek_event.network.src_ip} -> {zeek_event.network.dst_ip}:{zeek_event.network.dst_port} ({zeek_event.network.protocol})")
    print("  Zeek UID      :", zeek_event.raw_metadata.get("zeek_uid"))
    print("  Service       :", zeek_event.raw_metadata.get("service"))
    print("  Direction     :", zeek_event.network.direction)

    # Verification assertions
    assert suri_event.network.src_ip == zeek_event.network.src_ip == "192.168.1.10"
    assert suri_event.network.dst_ip == zeek_event.network.dst_ip == "192.168.1.20"
    assert suri_event.network.protocol == zeek_event.network.protocol == "TCP"
    assert suri_event.source == EventSource.SURICATA
    assert zeek_event.source == EventSource.ZEEK

    print("\n" + "=" * 65)
    print("SUCCESS: Both illustrative payloads transformed into unified NetrIQ standard events!")
    print("=" * 65)

if __name__ == "__main__":
    test_component_b_adapters()
