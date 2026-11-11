import time
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from backend.schemas.report import ReportGenerateReq, ReportMetadata
from backend.auth.roles import Capabilities, Role, get_request_role
from backend.auth.permissions import require_permission
from backend.services.report_service import report_service
from backend.utils.exceptions import DocumentNotFoundError
from backend.utils.logger import get_logger
from backend.database.collections import reports_repo

logger = get_logger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])


def _extract_authenticated_tenant(req: Request) -> str:
    """Extracts verified tenant_id from auth state or X-Tenant-ID for Admin."""
    auth_user = getattr(req.state, "user", None)
    if isinstance(auth_user, dict) and auth_user.get("tenant_id"):
        return auth_user.get("tenant_id")
    role = get_request_role(req)
    if role == Role.ADMIN:
        return req.headers.get("X-Tenant-ID", "global")
    return "default"


@router.get("", response_model=List[ReportMetadata], dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def list_reports(request: Request, limit: int = 50, skip: int = 0):
    """
    Retrieves generated historical reports scoped strictly to the caller's organisation.
    """
    try:
        tenant_id = _extract_authenticated_tenant(request)
        role = get_request_role(request)
        filter_q = {}
        if role != Role.ADMIN or tenant_id != "global":
            filter_q["tenant_id"] = tenant_id

        docs = await reports_repo.list(filter_query=filter_q, limit=limit, skip=skip, sort_by=[("created_at", -1)])
        return [ReportMetadata(**doc) for doc in docs]
    except Exception as e:
        logger.error(f"Failed to list reports: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve reports")


@router.post("/generate", response_model=ReportMetadata, dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def generate_report(req: ReportGenerateReq, request: Request):
    try:
        role = get_request_role(request)
        tenant_id = _extract_authenticated_tenant(request)
        now = time.time()
        start = req.start_time if req.start_time is not None else (now - 86400)
        end = req.end_time if req.end_time is not None else now
        report_id = await report_service.generate_report(
            role=role,
            report_type=req.report_type,
            start_time=start,
            end_time=end,
            format=req.format,
            tenant_id=tenant_id
        )
        return ReportMetadata(
            id=report_id,
            report_type=req.report_type,
            status="completed",
            download_url=f"/api/v1/reports/{report_id}/download"
        )
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to generate report")


@router.get("/download/{filename}", dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def download_report_by_filename(filename: str, request: Request):
    """
    Direct file download alias matching the download_url emitted during report creation.
    """
    try:
        role = get_request_role(request)
        tenant_id = _extract_authenticated_tenant(request)
        pdf_bytes, _ = await report_service.build_pdf(report_id="export", role=role, tenant_id=tenant_id)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except Exception as e:
        logger.error(f"Failed to download report {filename}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to download PDF: {e}")


@router.get("/{report_id}/download", dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def download_report_by_id(report_id: str, request: Request):
    """
    Streams a real ReportLab-generated SOC PDF document for the specified report ID with tenant authorization.
    """
    try:
        role = get_request_role(request)
        tenant_id = _extract_authenticated_tenant(request)
        pdf_bytes, filename = await report_service.build_pdf(report_id=report_id, role=role, tenant_id=tenant_id)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except Exception as e:
        logger.error(f"Failed to build PDF report {report_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to generate PDF: {e}")


@router.get("/{report_id}", response_model=ReportMetadata, dependencies=[Depends(require_permission(Capabilities.VIEW_SMART_SUMMARY))])
async def get_report(report_id: str, request: Request):
    try:
        role = get_request_role(request)
        tenant_id = _extract_authenticated_tenant(request)
        doc = await report_service.get_report(role=role, report_id=report_id, tenant_id=tenant_id)
        return ReportMetadata(**doc)
    except DocumentNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{report_id}' not found")
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except Exception as e:
        logger.error(f"Failed to retrieve report {report_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve report")
