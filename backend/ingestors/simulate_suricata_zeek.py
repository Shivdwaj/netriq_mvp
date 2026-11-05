import asyncio
import sys
import time
from datetime import datetime
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root_dir))

from dotenv import load_dotenv
load_dotenv(root_dir / "backend" / ".env")

from backend.database.database import DatabaseManager
from backend.pipeline import event_bus, identity_resolver
from backend.ingestors.suricata_ingestor import suricata_ingestor
from backend.ingestors.zeek_ingestor import zeek_ingestor
from backend.services.correlation_service import correlation_engine
from backend.database.collections import incidents_repo

# Simulated Host in Inventory
ATTACKER_IP = "192.168.1.185"
TARGET_SERVER_IP = "192.168.1.10"

# 1. Zeek conn.log Sample: High frequency SYN sweep (Port Scan / S0 state)
now_base = time.time() - 30

ZEEK_PORT_SCAN_RECORDS = [
    {
        "ts": now_base + idx,
        "uid": f"Czeek_scan_{idx}",
        "id.orig_h": ATTACKER_IP,
        "id.orig_p": 49152 + idx,
        "id.resp_h": TARGET_SERVER_IP,
        "id.resp_p": port,
        "proto": "tcp",
        "service": "-",
        "duration": 0.001,
        "orig_bytes": 0,
        "resp_bytes": 0,
        "conn_state": "S0", # Unresponsive SYN scan
        "history": "S"
    }
    for idx, port in enumerate(range(1001, 1014))
]

# 2. Suricata EVE Alert Record: Signature Match (Exploit / Nmap Scan)
SURICATA_ALERT_RECORD = {
    "timestamp": datetime.fromtimestamp(now_base + 15).isoformat(),
    "event_type": "alert",
    "src_ip": ATTACKER_IP,
    "src_port": 50123,
    "dest_ip": TARGET_SERVER_IP,
    "dest_port": 445,
    "proto": "TCP",
    "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": 2010935,
        "rev": 3,
        "signature": "ET EXPLOIT Possible Lateral Movement via SMB Exec",
        "category": "Attempted Administrator Privilege Gain",
        "severity": 1
    }
}

# 3. Zeek conn.log Record: Successful Lateral SMB connection
ZEEK_SMB_CONN_RECORD = {
    "ts": now_base + 16,
    "uid": "Czeek_smb_session_01",
    "id.orig_h": ATTACKER_IP,
    "id.orig_p": 50123,
    "id.resp_h": TARGET_SERVER_IP,
    "id.resp_p": 445,
    "proto": "tcp",
    "service": "smb",
    "duration": 4.52,
    "orig_bytes": 14200,
    "resp_bytes": 89000,
    "conn_state": "SF", # Established and completed
    "history": "ShADadFf"
}

# 4. Suricata EVE Alert Record: C2 Beacon Outbound
SURICATA_C2_RECORD = {
    "timestamp": datetime.fromtimestamp(now_base + 20).isoformat(),
    "event_type": "alert",
    "src_ip": ATTACKER_IP,
    "src_port": 54321,
    "dest_ip": "198.51.100.22", # External IP
    "dest_port": 8443,
    "proto": "TCP",
    "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": 2028911,
        "rev": 1,
        "signature": "ET TROJAN Cobalt Strike Beaconing Observed",
        "category": "A Network Trojan was detected",
        "severity": 1
    }
}

async def run_simulation():
    print("=" * 70)
    print("  NETRIQ MULTI-ENGINE FUSION SIMULATION: SURICATA + ZEEK")
    print("=" * 70)

    await DatabaseManager.connect_db()

    # Register host in identity resolver
    identity_resolver.register_device(
        ip=ATTACKER_IP,
        mac="00:1A:2B:3C:4D:5E",
        hostname="Laptop-Engineering-14",
        os_name="Ubuntu 22.04 LTS",
        logged_in_user="bob_dev",
        is_managed=True
    )

    # Subscribe correlation engine to event bus
    event_bus.subscribe(correlation_engine.process_event)

    print(f"\n[+] Ingesting Zeek conn.log ({len(ZEEK_PORT_SCAN_RECORDS)} SYN sweep connection records)...")
    for r in ZEEK_PORT_SCAN_RECORDS:
        ev = zeek_ingestor.parse_conn_record(r)
        if ev:
            await event_bus.publish(ev)

    print("\n[+] Ingesting Suricata EVE JSON (Signature Alert: SMB Lateral Exec)...")
    suri_ev1 = suricata_ingestor.parse_eve_record(SURICATA_ALERT_RECORD)
    if suri_ev1:
        await event_bus.publish(suri_ev1)

    print("\n[+] Ingesting Zeek conn.log (Established SMB Session metadata)...")
    zeek_ev_smb = zeek_ingestor.parse_conn_record(ZEEK_SMB_CONN_RECORD)
    if zeek_ev_smb:
        await event_bus.publish(zeek_ev_smb)

    print("\n[+] Ingesting Suricata EVE JSON (Signature Alert: Cobalt Strike C2)...")
    suri_ev2 = suricata_ingestor.parse_eve_record(SURICATA_C2_RECORD)
    if suri_ev2:
        await event_bus.publish(suri_ev2)

    # Allow async correlation to process
    await asyncio.sleep(1.0)

    # Check generated incident in MongoDB
    tracker = correlation_engine._trackers.get(ATTACKER_IP)
    assert tracker and tracker.active_incident_id, "Correlator did not generate an incident"

    incident = await incidents_repo.get(tracker.active_incident_id)

    print("\n" + "#" * 70)
    print("  NETRIQ SECURITY INTELLIGENCE VERDICT (Cross-Engine Incident)")
    print("#" * 70)
    print(f"  Incident Code : {incident.get('incident_code', 'INC-CORR')}")
    print(f"  Incident ID   : {incident.get('id')}")
    print(f"  Title         : {incident.get('title')}")
    print(f"  Severity      : {incident.get('severity')} (Confidence: {incident.get('confidence')})")
    print(f"  Host Entity   : {incident.get('hostname')} ({incident.get('src_ip')}) | User: {incident.get('user')}")
    print("\n  Synthesized Attack Chain (MITRE ATT&CK):")
    for stage in incident.get("attack_chain", []):
        print(f"    -> {stage}")
    print("\n  Recommended SOC Investigation Steps:")
    for step in incident.get("recommended_investigation_steps", []):
        print(f"    [ ] {step}")
    print(f"\n  Forensic Evidence Captured: {len(incident.get('evidence', []))} items from Suricata & Zeek")
    print("#" * 70)

    # Clean up test incident from database
    from bson import ObjectId
    await incidents_repo.collection.delete_one({"_id": ObjectId(tracker.active_incident_id)})
    await DatabaseManager.close_db()
    print("\n[OK] Simulation completed with 100% success!")

if __name__ == "__main__":
    asyncio.run(run_simulation())
