import pytest
import time
from unittest.mock import AsyncMock, MagicMock, patch
from bson import ObjectId

from backend.schemas.incident import IncidentStatus
from backend.services.incident_service import incident_service
from backend.database.collections import incidents_repo
from backend.database.database import DatabaseManager

@pytest.fixture(autouse=True)
def setup_mock_db():
    mock_db = MagicMock()
    mock_col = MagicMock()
    mock_db.__getitem__.return_value = mock_col
    DatabaseManager.db = mock_db
    return mock_col

@pytest.mark.asyncio
async def test_incident_state_machine_and_audit_history(setup_mock_db):
    """
    Validates the Incident Management Engine state machine:
    New -> Investigating -> Confirmed -> Resolved.
    Ensures every status change records user, timestamp, and justification reason in audit history.
    """
    test_id = str(ObjectId())
    incident_store = {
        "_id": ObjectId(test_id),
        "id": test_id,
        "tenant_id": "test_org",
        "incident_code": "INC-701",
        "status": IncidentStatus.NEW.value,
        "severity": "MEDIUM",
        "description": "Multi-stage port scan and lateral attempt",
        "created_at": time.time(),
        "audit_history": [],
        "investigation_notes": [],
        "evidence": []
    }

    async def mock_get(item_id, *args, **kwargs):
        if str(item_id) == test_id:
            return dict(incident_store)
        return None

    async def mock_update_one(filter_dict, update_dict):
        if "$set" in update_dict:
            incident_store.update(update_dict["$set"])
        if "$push" in update_dict:
            for k, v in update_dict["$push"].items():
                if k not in incident_store:
                    incident_store[k] = []
                incident_store[k].append(v)
        return True

    setup_mock_db.update_one = AsyncMock(side_effect=mock_update_one)

    with patch.object(incidents_repo, "get", side_effect=mock_get):
        # 1. Transition: New -> Investigating
        updated = await incident_service.update_status(
            incident_id=test_id,
            new_status="investigating",
            user="analyst_alice",
            reason="Starting triage on reconnaissance telemetry",
            tenant_id="test_org"
        )
        assert updated["status"] == "investigating"
        assert len(updated["audit_history"]) == 1
        entry1 = updated["audit_history"][0]
        assert entry1["action"] == "STATUS_CHANGE"
        assert entry1["user"] == "analyst_alice"
        assert entry1["reason"] == "Starting triage on reconnaissance telemetry"
        assert entry1["details"]["from_status"] == "new"
        assert entry1["details"]["to_status"] == "investigating"

        # 2. Transition: Investigating -> Confirmed
        updated2 = await incident_service.update_status(
            incident_id=test_id,
            new_status="confirmed",
            user="analyst_bob",
            reason="Confirmed malicious cobalt strike malleable profile",
            tenant_id="test_org"
        )
        assert updated2["status"] == "confirmed"
        assert len(updated2["audit_history"]) == 2
        entry2 = updated2["audit_history"][1]
        assert entry2["details"]["from_status"] == "investigating"
        assert entry2["details"]["to_status"] == "confirmed"

        # 3. Transition: Confirmed -> Resolved
        updated3 = await incident_service.update_status(
            incident_id=test_id,
            new_status="resolved",
            user="lead_soc",
            reason="Host quarantined and malicious processes purged",
            resolution_notes="Device isolated, credentials rotated",
            tenant_id="test_org"
        )
        assert updated3["status"] == "resolved"
        assert updated3["closed_by"] == "lead_soc"
        assert updated3["resolution_notes"] == "Device isolated, credentials rotated"
        assert len(updated3["audit_history"]) == 3

@pytest.mark.asyncio
async def test_invalid_status_transition_rejected(setup_mock_db):
    """Validates that invalid transitions along the state machine are rejected."""
    test_id = str(ObjectId())
    incident_store = {
        "_id": ObjectId(test_id),
        "id": test_id,
        "tenant_id": "test_org",
        "status": IncidentStatus.RESOLVED.value,
        "audit_history": []
    }

    async def mock_get(item_id, *args, **kwargs):
        return dict(incident_store)

    with patch.object(incidents_repo, "get", side_effect=mock_get):
        # Once resolved, valid transition is only back to investigating (re-open)
        with pytest.raises(ValueError) as excinfo:
            await incident_service.update_status(
                incident_id=test_id,
                new_status="confirmed",
                user="analyst_alice",
                reason="Invalid jump from resolved to confirmed",
                tenant_id="test_org"
            )
        assert "Invalid status transition" in str(excinfo.value)

@pytest.mark.asyncio
async def test_analyst_assignment_and_notes(setup_mock_db):
    """
    Validates analyst assignment and threaded investigation notes.
    Auto-advances status from New to Investigating when assigned.
    """
    test_id = str(ObjectId())
    incident_store = {
        "_id": ObjectId(test_id),
        "id": test_id,
        "tenant_id": "test_org",
        "status": IncidentStatus.NEW.value,
        "assigned_to": None,
        "audit_history": [],
        "investigation_notes": []
    }

    async def mock_get(item_id, *args, **kwargs):
        return dict(incident_store)

    async def mock_update_one(filter_dict, update_dict):
        if "$set" in update_dict:
            incident_store.update(update_dict["$set"])
        if "$push" in update_dict:
            for k, v in update_dict["$push"].items():
                if k not in incident_store:
                    incident_store[k] = []
                incident_store[k].append(v)
        return True

    setup_mock_db.update_one = AsyncMock(side_effect=mock_update_one)

    with patch.object(incidents_repo, "get", side_effect=mock_get):
        # 1. Assign analyst
        assigned = await incident_service.assign_analyst(
            incident_id=test_id,
            assigned_to="shiva.sec",
            user="soc_manager",
            reason="Assigning Tier-2 investigation",
            tenant_id="test_org"
        )
        assert assigned["assigned_to"] == "shiva.sec"
        assert assigned["status"] == "investigating" # auto-advanced from new
        assert len(assigned["audit_history"]) == 1
        assert assigned["audit_history"][0]["action"] == "ASSIGNMENT"
        assert assigned["audit_history"][0]["details"]["assigned_to"] == "shiva.sec"

        # 2. Append investigation note
        noted = await incident_service.add_note(
            incident_id=test_id,
            author="shiva.sec",
            content="Observed suspicious SMB exec command lines referencing PsExec service installation.",
            tenant_id="test_org"
        )
        assert len(noted["investigation_notes"]) == 1
        note_entry = noted["investigation_notes"][0]
        assert note_entry["author"] == "shiva.sec"
        assert "PsExec" in note_entry["content"]
        assert len(noted["audit_history"]) == 2
        assert noted["audit_history"][1]["action"] == "NOTE_ADDED"

@pytest.mark.asyncio
async def test_severity_override_and_evidence_attachment(setup_mock_db):
    """Validates severity changes with mandatory justification and forensic evidence attachment."""
    test_id = str(ObjectId())
    incident_store = {
        "_id": ObjectId(test_id),
        "id": test_id,
        "tenant_id": "test_org",
        "severity": "LOW",
        "audit_history": [],
        "evidence": []
    }

    async def mock_get(item_id, *args, **kwargs):
        return dict(incident_store)

    async def mock_update_one(filter_dict, update_dict):
        if "$set" in update_dict:
            incident_store.update(update_dict["$set"])
        if "$push" in update_dict:
            for k, v in update_dict["$push"].items():
                if k not in incident_store:
                    incident_store[k] = []
                incident_store[k].append(v)
        return True

    setup_mock_db.update_one = AsyncMock(side_effect=mock_update_one)

    with patch.object(incidents_repo, "get", side_effect=mock_get):
        # 1. Change severity
        sev_updated = await incident_service.change_severity(
            incident_id=test_id,
            new_severity="CRITICAL",
            user="soc_lead",
            reason="Target is Crown Jewel Database Host containing PII",
            tenant_id="test_org"
        )
        assert sev_updated["severity"] == "CRITICAL"
        assert len(sev_updated["audit_history"]) == 1
        entry = sev_updated["audit_history"][0]
        assert entry["action"] == "SEVERITY_CHANGE"
        assert entry["details"]["old_severity"] == "LOW"
        assert entry["details"]["new_severity"] == "CRITICAL"
        assert entry["reason"] == "Target is Crown Jewel Database Host containing PII"

        # 2. Attach evidence
        ev_item = {
            "source": "suricata_eve",
            "summary": "ET EXPLOIT Possible Lateral Movement via SMB Exec",
            "sid": 2010935
        }
        ev_attached = await incident_service.attach_evidence(
            incident_id=test_id,
            evidence_item=ev_item,
            user="soc_lead",
            reason="Suricata alert matches timestamp of initial connection",
            tenant_id="test_org"
        )
        assert len(ev_attached["evidence"]) == 1
        assert len(ev_attached["audit_history"]) == 2
        ev_entry = ev_attached["audit_history"][1]
        assert ev_entry["action"] == "EVIDENCE_ATTACHED"
        assert ev_entry["details"]["source"] == "suricata_eve"
