from fastapi import APIRouter, Depends, HTTPException, Request, status
from typing import List, Dict, Any, Optional

from backend.schemas.incident import (
    IncidentItem,
    IncidentUpdateReq,
    IncidentStatusUpdateReq,
    IncidentAssignmentReq,
    IncidentNoteReq,
    IncidentSeverityUpdateReq,
    IncidentEvidenceAttachReq,
    AuditEntry
)
from backend.auth.roles import Capabilities, get_request_role
from backend.auth.permissions import require_permission
from backend.services.incident_service import incident_service
from backend.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/incidents", tags=["incidents"])

def _get_request_user(req: Request) -> str:
    """Extracts username or identity from request auth state."""
    auth_user = getattr(req.state, "user", None)
    if isinstance(auth_user, dict):
        return auth_user.get("username") or auth_user.get("sub") or "analyst@netriq.local"
    if isinstance(auth_user, str):
        return auth_user
    return "analyst@netriq.local"

def _get_request_tenant(req: Request) -> Optional[str]:
    """Extracts tenant_id from auth state or X-Tenant-ID header."""
    auth_user = getattr(req.state, "user", None)
    if isinstance(auth_user, dict) and auth_user.get("tenant_id"):
        return auth_user.get("tenant_id")
    return req.headers.get("X-Tenant-ID", "default")

@router.get("", response_model=List[IncidentItem], dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def list_incidents(req: Request):
    """Lists incidents scoped to the requester's organisation."""
    try:
        role = get_request_role(req)
        tenant_id = _get_request_tenant(req)
        results = await incident_service.list(role=role, tenant_id=tenant_id, limit=100)
        return [IncidentItem(**item) for item in results]
    except Exception as e:
        logger.error(f"Failed to list incidents: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve incidents")

@router.get("/{incident_id}", response_model=IncidentItem, dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def get_incident(incident_id: str, req: Request):
    """Retrieves an incident by ID with tenant access control."""
    try:
        tenant_id = _get_request_tenant(req)
        item = await incident_service.get(incident_id, tenant_id=tenant_id)
        if not item:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
        return IncidentItem(**item)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get incident {incident_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve incident")

@router.patch("/{incident_id}/status", response_model=IncidentItem, dependencies=[Depends(require_permission(Capabilities.REVERSE_RESPONSE_ACTION))])
async def update_incident_status(incident_id: str, body: IncidentStatusUpdateReq, req: Request):
    """
    Transitions incident status (New -> Investigating -> Confirmed / False Positive -> Resolved).
    Records an immutable audit entry with actor, timestamp, and reason.
    """
    try:
        user = _get_request_user(req)
        tenant_id = _get_request_tenant(req)
        updated = await incident_service.update_status(
            incident_id=incident_id,
            new_status=body.status,
            user=user,
            reason=body.reason,
            resolution_notes=body.resolution_notes,
            tenant_id=tenant_id
        )
        return IncidentItem(**updated)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as e:
        logger.error(f"Failed to update status for incident {incident_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update incident status")

@router.post("/{incident_id}/assign", response_model=IncidentItem, dependencies=[Depends(require_permission(Capabilities.REVERSE_RESPONSE_ACTION))])
async def assign_incident_analyst(incident_id: str, body: IncidentAssignmentReq, req: Request):
    """Assigns an incident to an analyst with audit history."""
    try:
        user = _get_request_user(req)
        tenant_id = _get_request_tenant(req)
        updated = await incident_service.assign_analyst(
            incident_id=incident_id,
            assigned_to=body.assigned_to,
            user=user,
            reason=body.reason,
            tenant_id=tenant_id
        )
        return IncidentItem(**updated)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as e:
        logger.error(f"Failed to assign analyst for incident {incident_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to assign analyst")

@router.post("/{incident_id}/notes", response_model=IncidentItem, dependencies=[Depends(require_permission(Capabilities.REVERSE_RESPONSE_ACTION))])
async def add_investigation_note(incident_id: str, body: IncidentNoteReq, req: Request):
    """Appends an investigation note and records audit trail."""
    try:
        user = _get_request_user(req)
        tenant_id = _get_request_tenant(req)
        updated = await incident_service.add_note(
            incident_id=incident_id,
            author=user,
            content=body.content,
            tenant_id=tenant_id
        )
        return IncidentItem(**updated)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as e:
        logger.error(f"Failed to add note to incident {incident_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to add investigation note")

@router.patch("/{incident_id}/severity", response_model=IncidentItem, dependencies=[Depends(require_permission(Capabilities.REVERSE_RESPONSE_ACTION))])
async def change_incident_severity(incident_id: str, body: IncidentSeverityUpdateReq, req: Request):
    """Overrides incident severity with mandatory justification logged in audit history."""
    try:
        user = _get_request_user(req)
        tenant_id = _get_request_tenant(req)
        updated = await incident_service.change_severity(
            incident_id=incident_id,
            new_severity=body.severity,
            user=user,
            reason=body.reason,
            tenant_id=tenant_id
        )
        return IncidentItem(**updated)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as e:
        logger.error(f"Failed to change severity for incident {incident_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to change incident severity")

@router.post("/{incident_id}/evidence", response_model=IncidentItem, dependencies=[Depends(require_permission(Capabilities.REVERSE_RESPONSE_ACTION))])
async def attach_incident_evidence(incident_id: str, body: IncidentEvidenceAttachReq, req: Request):
    """Attaches new forensic indicator or event to the incident."""
    try:
        user = _get_request_user(req)
        tenant_id = _get_request_tenant(req)
        updated = await incident_service.attach_evidence(
            incident_id=incident_id,
            evidence_item=body.evidence,
            user=user,
            reason=body.reason,
            tenant_id=tenant_id
        )
        return IncidentItem(**updated)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as e:
        logger.error(f"Failed to attach evidence to incident {incident_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to attach evidence")

@router.get("/{incident_id}/audit-history", response_model=List[AuditEntry], dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def get_incident_audit_history(incident_id: str, req: Request):
    """Returns the full chronological audit history for an incident."""
    try:
        tenant_id = _get_request_tenant(req)
        history = await incident_service.get_audit_history(incident_id, tenant_id=tenant_id)
        return [AuditEntry(**entry) for entry in history]
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as e:
        logger.error(f"Failed to get audit history for incident {incident_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve audit history")

@router.patch("/{incident_id}", response_model=IncidentItem, dependencies=[Depends(require_permission(Capabilities.REVERSE_RESPONSE_ACTION))])
async def update_incident(incident_id: str, req: IncidentUpdateReq, request: Request):
    """Legacy update endpoint maintaining backward compatibility."""
    try:
        tenant_id = _get_request_tenant(request)
        updates = req.model_dump(exclude_unset=True)
        updated = await incident_service.update(incident_id, updates, tenant_id=tenant_id)
        return IncidentItem(**updated)
    except Exception as e:
        logger.error(f"Failed to update incident {incident_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update incident")

@router.get("/{incident_id}/countermeasures", dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def get_incident_countermeasures(incident_id: str):
    try:
        return await incident_service.get_countermeasures(incident_id)
    except Exception as e:
        logger.error(f"Failed to get countermeasures for {incident_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to generate countermeasures")

@router.get("/{incident_id}/evidence", dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def list_incident_evidence(incident_id: str, req: Request):
    """
    Lists external forensic evidence records (PCAPs, memory dumps, logs)
    associated with this incident, including storage paths and SHA-256 hashes.
    """
    try:
        tenant_id = _get_request_tenant(req)
        from backend.database.collections import evidence_repo
        items = await evidence_repo.list_by_tenant(
            tenant_id=tenant_id,
            filter_query={"incident_id": incident_id},
            limit=50
        )
        return items
    except Exception as e:
        logger.error(f"Failed to retrieve evidence for incident {incident_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve evidence")

@router.get("/{incident_id}/events", dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def get_incident_events(incident_id: str, req: Request):
    """
    Retrieves the list of supporting network events linked to this incident
    via the incident_events join entity.
    Allows the analyst to navigate directly from an incident to its supporting events.
    """
    try:
        tenant_id = _get_request_tenant(req)
        from backend.database.collections import incident_events_repo, network_events_repo
        links = await incident_events_repo.list_by_tenant(
            tenant_id=tenant_id,
            filter_query={"incident_id": incident_id},
            limit=100
        )
        # Fetch associated network event records if available
        event_ids = [l["event_id"] for l in links if l.get("event_id")]
        events_by_id = {}
        if event_ids:
            raw_events = await network_events_repo.list_by_tenant(
                tenant_id=tenant_id,
                filter_query={"event_id": {"$in": event_ids}},
                limit=100
            )
            events_by_id = {e.get("event_id"): e for e in raw_events}

        enriched = []
        for l in links:
            item = dict(l)
            eid = l.get("event_id")
            if eid in events_by_id:
                item["network_event"] = events_by_id[eid]
            enriched.append(item)

        return enriched
    except Exception as e:
        logger.error(f"Failed to retrieve incident events for incident {incident_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve incident events")

@router.post("/{incident_id}/evidence/{evidence_id}/verify", dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def verify_incident_evidence(incident_id: str, evidence_id: str, req: Request):
    """
    Cryptographically verifies the SHA-256 checksum of an external PCAP evidence file.
    Guarantees forensic integrity and non-repudiation.
    """
    try:
        tenant_id = _get_request_tenant(req)
        from backend.services.evidence_service import evidence_service
        verification = await evidence_service.verify_evidence_integrity(
            evidence_id=evidence_id,
            tenant_id=tenant_id
        )
        return verification
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as e:
        logger.error(f"Failed to verify evidence {evidence_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to verify evidence")

@router.delete("/clear-all", dependencies=[Depends(require_permission(Capabilities.TRIGGER_QUARANTINE))])
async def clear_all_incidents():
    """Wipes historical test incident records so the live SOC console starts completely fresh."""
    try:
        from backend.database.collections import incidents_repo
        res = await incidents_repo.collection.delete_many({})
        logger.info(f"Cleared {res.deleted_count} historical incidents from MongoDB.")
        return {"status": "success", "deleted_count": res.deleted_count}
    except Exception as e:
        logger.error(f"Failed to clear incidents: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to clear incidents")
