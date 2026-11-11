import time
from typing import Dict, Any, List, Tuple
from backend.utils.logger import get_logger
from backend.auth.roles import Role
from backend.database.collections import reports_repo, threats_repo
from backend.utils.exceptions import DocumentNotFoundError
from backend.services.dashboard_service import dashboard_service
from backend.services.pdf_generator import build_soc_pdf_report

logger = get_logger(__name__)

class ReportService:
    async def generate_report(
        self,
        role: Role,
        report_type: str,
        start_time: float,
        end_time: float,
        format: str,
        tenant_id: str = "default"
    ) -> str:
        """
        Creates report record scoped to tenant and marks it completed.
        """
        record = {
            "report_type": report_type,
            "status": "completed",
            "format": format.lower(),
            "start_time": start_time,
            "end_time": end_time,
            "tenant_id": tenant_id,
            "created_at": time.time(),
            "download_url": f"/api/v1/reports/download/{report_type}.{format.lower()}",
        }
        report_id = await reports_repo.create(record)
        logger.info(f"Generated {format} report {report_id} for tenant '{tenant_id}' (status: completed)")
        return report_id
        
    async def get_report(self, role: Role, report_id: str, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        doc = await reports_repo.get(report_id)
        if not doc:
            raise DocumentNotFoundError(f"Report '{report_id}' not found")
        if tenant_id and tenant_id != "global" and doc.get("tenant_id") and doc.get("tenant_id") != tenant_id:
            raise PermissionError(f"Access denied to report '{report_id}' across tenant boundaries.")
        return doc

    async def build_pdf(self, report_id: str, role: Role, tenant_id: Optional[str] = None) -> Tuple[bytes, str]:
        """
        Retrieves real report telemetry and builds a real ReportLab PDF document with tenant scoping.
        """
        doc = {}
        if report_id != "export":
            doc = await self.get_report(role=role, report_id=report_id, tenant_id=tenant_id)

        report_type = doc.get("report_type", "incident_summary")
        now = time.time()
        start_time = doc.get("start_time", now - 86400)
        end_time = doc.get("end_time", now)
        rep_tenant = doc.get("tenant_id", tenant_id or "default")

        # Query real database threats
        recent_threats = await threats_repo.get_dashboard_stats(
            time_range_start=start_time,
            time_range_end=end_time,
            severity=None
        )
        if rep_tenant and rep_tenant != "global":
            recent_threats = [t for t in recent_threats if t.get("tenant_id", "default") == rep_tenant]

        # Get dashboard summary stats
        summary_stats = await dashboard_service.get_summary(role)

        pdf_bytes = build_soc_pdf_report(
            report_id=report_id,
            report_type=report_type,
            start_time=start_time,
            end_time=end_time,
            threats=recent_threats,
            summary_stats=summary_stats,
        )

        filename = f"netriq_{report_type}_{report_id[:8]}.pdf"
        return pdf_bytes, filename

report_service = ReportService()
