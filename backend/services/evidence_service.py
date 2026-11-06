"""
evidence_service.py
Service for managing supporting security evidence, external PCAP storage,
cryptographic verification, incident-to-event linkages, and audit logging.

Architectural Mandates:
1. Large PCAP files are stored outside the relational/document database.
   The database retains only file references, paths, and SHA-256 hashes.
2. Limited, configurable packet-capture window enforced via retention expiration.
3. Every operation is strictly tenant-scoped.
"""

import os
import time
import uuid
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timezone, timedelta

from backend.database.collections import (
    evidence_repo,
    incident_events_repo,
    audit_logs_repo,
    incidents_repo
)
from backend.schemas.entities import (
    Evidence,
    EvidenceType,
    IncidentEvent,
    IncidentEventRole,
    AuditLog,
    AuditAction,
    get_utc_now_iso,
    get_utc_now_timestamp
)
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Base storage directory for external raw PCAP and log artifacts
EVIDENCE_STORAGE_DIR = Path(os.getenv("EVIDENCE_STORAGE_DIR", "storage/evidence")).resolve()


class EvidenceService:
    """
    Manages forensic evidence artifacts, PCAP hashing, incident linking, and audit trails.
    """
    def __init__(self, base_storage_dir: Optional[Path] = None):
        self.storage_dir = base_storage_dir or EVIDENCE_STORAGE_DIR
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _build_pcap_bytes(self, packets: List[Dict[str, Any]]) -> bytes:
        """
        Synthesizes standard binary PCAP stream from structured packet slices.
        Includes Global Header + Packet Headers + Payload bytes.
        """
        # PCAP Global Header: 24 bytes (Magic 0xa1b2c3d4, v2.4, standard ethernet snaplen 65535)
        # magic(4B), major(2B), minor(2B), thiszone(4B), sigfigs(4B), snaplen(4B), network(4B: Ethernet=1)
        global_header = (
            b"\xd4\xc3\xb2\xa1"  # Little-endian magic
            b"\x02\x00\x04\x00"  # Version 2.4
            b"\x00\x00\x00\x00"  # GMT to local correction
            b"\x00\x00\x00\x00"  # Accuracy of timestamps
            b"\xff\xff\x00\x00"  # Max snaplen (65535)
            b"\x01\x00\x00\x00"  # Link-layer type: Ethernet (1)
        )

        pcap_body = bytearray(global_header)
        for pkt in packets:
            ts = float(pkt.get("timestamp", time.time()))
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)

            payload_hex = pkt.get("payload_hex", "")
            try:
                payload = bytes.fromhex(payload_hex) if payload_hex else b""
            except Exception:
                payload = b""

            if not payload:
                payload = b"\x00" * int(pkt.get("length", 64))

            caplen = len(payload)
            wirelen = int(pkt.get("length", caplen))

            # Packet Header: 16 bytes (ts_sec, ts_usec, caplen, wirelen)
            import struct
            pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, caplen, wirelen)
            pcap_body.extend(pkt_hdr)
            pcap_body.extend(payload)

        return bytes(pcap_body)

    async def store_selective_pcap(
        self,
        tenant_id: str,
        incident_id: str,
        sensor_id: str,
        packets: List[Dict[str, Any]],
        filter_criteria: Optional[Dict[str, Any]] = None,
        retention_days: int = 14
    ) -> Evidence:
        """
        Stores an extracted packet slice outside the database.
        Computes SHA-256 cryptographic digest and records reference in evidence repository.
        """
        evidence_id = f"evi-pcap-{uuid.uuid4().hex[:12]}"
        now = time.time()
        now_iso = get_utc_now_iso()
        expires_at = now + (retention_days * 86400)
        expires_at_iso = datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()

        # Build external storage directory: storage/evidence/<tenant_id>/<incident_id>/
        incident_dir = self.storage_dir / tenant_id / incident_id
        incident_dir.mkdir(parents=True, exist_ok=True)
        file_path = incident_dir / f"{evidence_id}.pcap"

        # Generate binary content and SHA-256 digest
        pcap_bytes = self._build_pcap_bytes(packets)
        file_hash = hashlib.sha256(pcap_bytes).hexdigest()
        file_size = len(pcap_bytes)

        # Write to external file storage
        with open(file_path, "wb") as f:
            f.write(pcap_bytes)

        relative_path = str(file_path.relative_to(self.storage_dir.parent)).replace("\\", "/")

        evidence = Evidence(
            evidence_id=evidence_id,
            tenant_id=tenant_id,
            incident_id=incident_id,
            sensor_id=sensor_id,
            evidence_type=EvidenceType.SELECTIVE_PCAP,
            file_path=relative_path,
            file_hash_sha256=file_hash,
            file_size_bytes=file_size,
            storage_backend="local_disk",
            packet_count=len(packets),
            filter_criteria=filter_criteria or {},
            captured_at=now,
            captured_at_iso=now_iso,
            expires_at=expires_at,
            expires_at_iso=expires_at_iso,
            is_immutable=True
        )

        doc = evidence.model_dump()
        doc["created_at"] = now
        await evidence_repo.create(doc)

        logger.info(
            f"[EvidenceService] Stored selective PCAP evidence {evidence_id} for incident {incident_id} "
            f"({len(packets)} pkts, {file_size} bytes, sha256={file_hash[:16]}...)"
        )
        return evidence

    async def verify_evidence_integrity(self, evidence_id: str, tenant_id: str) -> Dict[str, Any]:
        """
        Verifies the cryptographic integrity of an external PCAP file against its stored SHA-256 hash.
        Guarantees non-repudiation and tamper-evident SOC forensic proof.
        """
        results = await evidence_repo.list_by_tenant(tenant_id, filter_query={"evidence_id": evidence_id}, limit=1)
        if not results:
            raise ValueError(f"Evidence '{evidence_id}' not found for tenant '{tenant_id}'.")

        doc = results[0]
        stored_hash = doc.get("file_hash_sha256")
        file_path_str = doc.get("file_path", "")

        # Resolve full path on disk
        full_path = self.storage_dir.parent / file_path_str
        if not full_path.exists():
            return {
                "evidence_id": evidence_id,
                "verified": False,
                "error": f"Underlying storage file missing: {file_path_str}",
                "stored_hash": stored_hash
            }

        with open(full_path, "rb") as f:
            content = f.read()
        computed_hash = hashlib.sha256(content).hexdigest()

        is_valid = (computed_hash == stored_hash)
        return {
            "evidence_id": evidence_id,
            "tenant_id": tenant_id,
            "verified": is_valid,
            "stored_hash": stored_hash,
            "computed_hash": computed_hash,
            "file_size_bytes": len(content),
            "file_path": file_path_str,
            "is_tampered": not is_valid
        }

    async def link_event_to_incident(
        self,
        tenant_id: str,
        incident_id: str,
        event_id: str,
        alert_id: Optional[str] = None,
        role_in_incident: IncidentEventRole = IncidentEventRole.SUPPORTING,
        timestamp: Optional[str] = None
    ) -> IncidentEvent:
        """
        Creates an incident_events join record linking a network event / alert to an incident.
        """
        now = time.time()
        inc_event = IncidentEvent(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            incident_id=incident_id,
            event_id=event_id,
            alert_id=alert_id,
            timestamp=timestamp or get_utc_now_iso(),
            timestamp_epoch=now,
            role_in_incident=role_in_incident,
            added_at=now,
            added_at_iso=get_utc_now_iso()
        )
        await incident_events_repo.create(inc_event.model_dump())
        return inc_event

    async def log_audit_action(
        self,
        tenant_id: str,
        user_id: str,
        username: str,
        action: Union[AuditAction, str],
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        status: str = "SUCCESS"
    ) -> AuditLog:
        """
        Appends an immutable audit log entry for user or administrative actions.
        """
        audit_entry = AuditLog(
            audit_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            user_id=user_id,
            username=username,
            action=action.value if isinstance(action, AuditAction) else action,
            resource_type=resource_type,
            resource_id=resource_id,
            timestamp=get_utc_now_timestamp(),
            timestamp_iso=get_utc_now_iso(),
            details=details or {},
            ip_address=ip_address,
            status=status
        )
        await audit_logs_repo.create(audit_entry.model_dump())
        return audit_entry


evidence_service = EvidenceService()
