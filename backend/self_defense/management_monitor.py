"""
backend/self_defense/management_monitor.py

Management Security Monitor (MSM) for NetrIQ Stage 2 Self-Defense.
Implements:
1. Canary Token & Tripwire Detection (honeypot keys, accounts, and DB markers).
2. Administrative Anomaly Detection & Rate Limiting (bursts, bulk deletions, rapid provisioning).
3. Fail-Closed Audit Enforcement (mutations strictly blocked if audit ledger fails).
4. Dual-Approval (Two-Man Rule) for high-impact administrative operations.
5. Multi-tenant administrative isolation enforcement.
6. Independent out-of-band alert dispatch on security violations.
"""

import os
import time
import secrets
import hashlib
from typing import Dict, Any, Optional, List, Set, Union
from fastapi import Request, HTTPException, status

from backend.utils.logger import get_logger
from backend.self_defense.schemas import (
    CanaryTokenType,
    CanaryTriggerEvent,
    AdminAnomalyType,
    DualApprovalRecord,
    SecurityAlert,
    AlertSeverity,
    AlertCategory,
    get_utc_now_timestamp,
    get_utc_now_iso,
)
from backend.self_defense.audit_ledger import (
    CryptographicallySealedAuditLedger,
    AuditStorageError,
    audit_ledger as global_audit_ledger,
)
from backend.self_defense.watchdog import (
    AlertSink,
    FileAlertSink,
    MemoryAlertSink,
)

logger = get_logger(__name__)

# Configurable limits
DEFAULT_ADMIN_BURST_LIMIT = int(os.getenv("NETRIQ_ADMIN_BURST_LIMIT", "10"))  # actions per 10s
DEFAULT_ADMIN_BURST_WINDOW = float(os.getenv("NETRIQ_ADMIN_BURST_WINDOW", "10.0"))
DEFAULT_USER_PROVISION_LIMIT = int(os.getenv("NETRIQ_USER_PROVISION_LIMIT", "5"))  # per 60s
DEFAULT_USER_PROVISION_WINDOW = float(os.getenv("NETRIQ_USER_PROVISION_WINDOW", "60.0"))
DEFAULT_BULK_DELETE_LIMIT = int(os.getenv("NETRIQ_BULK_DELETE_LIMIT", "5"))


# ==============================================================================
# Exceptions
# ==============================================================================

class ManagementSecurityError(Exception):
    """Base exception for management security violations."""
    def __init__(self, message: str, anomaly_type: AdminAnomalyType, status_code: int = 403):
        super().__init__(message)
        self.anomaly_type = anomaly_type
        self.status_code = status_code


class AdminAnomalyError(ManagementSecurityError):
    def __init__(self, message: str, anomaly_type: AdminAnomalyType = AdminAnomalyType.BURST_ACTIVITY, status_code: int = 429):
        super().__init__(message, anomaly_type, status_code=status_code)


class DualApprovalRequiredError(ManagementSecurityError):
    def __init__(self, message: str = "Two-man authorization rule violation: Dual approval required for high-impact action."):
        super().__init__(message, AdminAnomalyType.DUAL_APPROVAL_MISSING, status_code=403)


class FailClosedAuditError(ManagementSecurityError):
    def __init__(self, message: str = "Administrative operation rejected: Audit ledger storage failure (fail-closed mandate)."):
        super().__init__(message, AdminAnomalyType.AUDIT_STORAGE_FAILURE, status_code=503)


# ==============================================================================
# Management Security Monitor (MSM) Engine
# ==============================================================================

class ManagementSecurityMonitor:
    """
    Central Management Security Monitor (MSM).
    Secures the administrative control plane against credential abuse,
    canary probes, rapid manipulation, and un-audited state mutations.
    """

    def __init__(
        self,
        audit_ledger: Optional[CryptographicallySealedAuditLedger] = None,
        alert_sinks: Optional[List[AlertSink]] = None,
    ):
        self.audit_ledger = audit_ledger or global_audit_ledger
        self.alert_sinks: List[AlertSink] = alert_sinks or []
        if not self.alert_sinks:
            self.alert_sinks.append(FileAlertSink())

        # Canary token registries (token_value or token_hash -> metadata)
        self._canary_tokens: Dict[str, Dict[str, Any]] = {}
        self._canary_usernames: Set[str] = set()

        # Anomaly rate tracking: actor_id -> List of timestamps
        self._action_history: Dict[str, List[float]] = {}
        self._user_provision_history: Dict[str, List[float]] = {}

        # Dual approval store: token -> DualApprovalRecord
        self._dual_approval_store: Dict[str, DualApprovalRecord] = {}

        # High impact action definitions
        self.high_impact_actions: Set[str] = {
            "PURGE_ALL_SENSORS",
            "PURGE_ALL_RULES",
            "GLOBAL_SYSTEM_RESET",
            "MASTER_KEY_ROTATION",
            "BULK_DELETE_USERS",
            "THRESHOLD_OVERRIDE_GLOBAL",
        }

        # Initialize default synthetic honeypots
        self._init_default_canaries()

    def _init_default_canaries(self):
        """Initializes default synthetic canary credentials and honeypot markers."""
        self.register_canary_token(
            token_value="netriq_canary_superadmin_secret_token_999",
            token_type=CanaryTokenType.API_KEY,
            description="Synthetic high-privilege master key honeypot",
        )
        self.register_canary_token(
            token_value="canary_admin@netriq.local",
            token_type=CanaryTokenType.USER_ACCOUNT,
            description="Synthetic dormant administrator honeypot",
        )
        self.register_canary_token(
            token_value="emergency_override_key_tripwire_2026",
            token_type=CanaryTokenType.API_KEY,
            description="Synthetic emergency override key tripwire",
        )

    def add_alert_sink(self, sink: AlertSink) -> None:
        """Registers an out-of-band alert sink."""
        self.alert_sinks.append(sink)

    async def broadcast_alert(self, alert: SecurityAlert) -> None:
        """Dispatches out-of-band alert across all sinks."""
        for sink in self.alert_sinks:
            try:
                await sink.emit_alert(alert)
            except Exception as e:
                logger.error(f"[MSM] Error broadcasting alert: {e}")

    # --------------------------------------------------------------------------
    # 1. Canary Token Honeypot Detection
    # --------------------------------------------------------------------------

    def register_canary_token(
        self,
        token_value: str,
        token_type: CanaryTokenType,
        description: str = "",
        tenant_id: str = "global",
    ) -> str:
        """Registers a synthetic canary token to be tripwire monitored."""
        clean_val = token_value.strip()
        val_hash = hashlib.sha256(clean_val.encode("utf-8")).hexdigest()
        self._canary_tokens[clean_val] = {
            "hash": val_hash,
            "type": token_type,
            "description": description,
            "tenant_id": tenant_id,
        }
        self._canary_tokens[val_hash] = {
            "hash": val_hash,
            "type": token_type,
            "description": description,
            "tenant_id": tenant_id,
        }
        if token_type == CanaryTokenType.USER_ACCOUNT:
            self._canary_usernames.add(clean_val.lower())
        return val_hash

    async def check_canary_probe(
        self,
        candidate_value: str,
        source_ip: str = "unknown",
        endpoint: str = "unknown",
        method: str = "POST",
    ) -> bool:
        """
        Evaluates candidate credential or token against synthetic canary registry.
        If a canary is matched:
        - Logs CRITICAL alert to watchdog sink.
        - Records in sealed audit ledger.
        - Returns True.
        Note: The caller MUST return a generic rejection (401/404) without indicating a canary was tripped!
        """
        if not candidate_value:
            return False

        clean_candidate = candidate_value.strip()
        matched = False
        meta = None

        if clean_candidate in self._canary_tokens:
            matched = True
            meta = self._canary_tokens[clean_candidate]
        elif clean_candidate.lower() in self._canary_usernames:
            matched = True
            meta = self._canary_tokens.get(clean_candidate.lower(), {"type": CanaryTokenType.USER_ACCOUNT})
        else:
            cand_hash = hashlib.sha256(clean_candidate.encode("utf-8")).hexdigest()
            if cand_hash in self._canary_tokens:
                matched = True
                meta = self._canary_tokens[cand_hash]

        if matched:
            token_type = meta.get("type", CanaryTokenType.API_KEY)
            token_desc = meta.get("description", "Synthetic canary")
            logger.critical(
                f"[MSM] CANARY TRIPWIRE ACTIVATED: Source={source_ip}, Endpoint={endpoint}, "
                f"Type={token_type.value}, Desc={token_desc}"
            )

            # 1. Out-of-band alert
            alert = SecurityAlert(
                severity=AlertSeverity.CRITICAL,
                category=AlertCategory.CANARY_TRIGGERED,
                source="management_monitor.canary_guard",
                message=f"Honeypot canary credential probed at {endpoint} by {source_ip}",
                details={
                    "source_ip": source_ip,
                    "endpoint": endpoint,
                    "method": method,
                    "canary_type": token_type.value,
                    "description": token_desc,
                },
            )
            await self.broadcast_alert(alert)

            # 2. Record in sealed audit ledger
            try:
                await self.audit_ledger.append_entry(
                    action="CANARY_TRIPWIRE_TRIGGERED",
                    resource_type="canary_token",
                    resource_id=token_desc,
                    actor={"ip": source_ip, "probed_value": clean_candidate[:4] + "***"},
                    details={"endpoint": endpoint, "method": method, "source_ip": source_ip},
                    tenant_id=meta.get("tenant_id", "global"),
                    status="DENIED",
                )
            except Exception as e:
                logger.error(f"[MSM] Failed to record canary trigger in audit ledger: {e}")

            return True

        return False

    # --------------------------------------------------------------------------
    # 2. Administrative Anomaly Detection & Rate Limiting
    # --------------------------------------------------------------------------

    def check_admin_rate_limits(
        self,
        actor_id: str,
        action: str,
        item_count: int = 1,
        tenant_id: str = "global",
    ) -> None:
        """
        Enforces administrative mutation rate boundaries and detects anomalies:
        - Rejects rapid burst actions (> 10 actions per 10s).
        - Rejects unapproved bulk deletions (> 5 items in one call).
        - Rejects rapid user provisioning (> 5 users in 60s).
        """
        now = get_utc_now_timestamp()

        # Check 1: Bulk Deletions
        if "DELETE" in action.upper() or "PURGE" in action.upper():
            if item_count > DEFAULT_BULK_DELETE_LIMIT:
                logger.warning(
                    f"[MSM] Bulk deletion anomaly detected for actor {actor_id} (count={item_count} > {DEFAULT_BULK_DELETE_LIMIT})"
                )
                raise AdminAnomalyError(
                    f"Bulk deletion limit exceeded ({item_count} items requested, maximum {DEFAULT_BULK_DELETE_LIMIT}). "
                    "Dual-approval authorization required for bulk operations.",
                    AdminAnomalyType.BULK_DELETION,
                    status_code=403,
                )

        # Check 2: Rapid User Provisioning
        if action in ("REGISTER_USER", "CREATE_USER", "INITIAL_SETUP"):
            user_hist = self._user_provision_history.setdefault(actor_id, [])
            cutoff_user = now - DEFAULT_USER_PROVISION_WINDOW
            self._user_provision_history[actor_id] = [t for t in user_hist if t >= cutoff_user]
            if len(self._user_provision_history[actor_id]) >= DEFAULT_USER_PROVISION_LIMIT:
                logger.warning(f"[MSM] Rapid user provisioning rate limit exceeded for actor {actor_id}")
                raise AdminAnomalyError(
                    f"Rapid user creation rate limit exceeded (maximum {DEFAULT_USER_PROVISION_LIMIT} per minute).",
                    AdminAnomalyType.RAPID_USER_PROVISIONING,
                    status_code=429,
                )
            self._user_provision_history[actor_id].append(now)

        # Check 3: General Admin Mutation Burst
        hist = self._action_history.setdefault(actor_id, [])
        cutoff_burst = now - DEFAULT_ADMIN_BURST_WINDOW
        self._action_history[actor_id] = [t for t in hist if t >= cutoff_burst]

        if len(self._action_history[actor_id]) >= DEFAULT_ADMIN_BURST_LIMIT:
            logger.warning(f"[MSM] Administrative burst limit exceeded for actor {actor_id}")
            raise AdminAnomalyError(
                f"Administrative rate limit exceeded ({DEFAULT_ADMIN_BURST_LIMIT} mutations per {DEFAULT_ADMIN_BURST_WINDOW}s).",
                AdminAnomalyType.BURST_ACTIVITY,
                status_code=429,
            )
        self._action_history[actor_id].append(now)

    # --------------------------------------------------------------------------
    # 3. Mandatory Fail-Closed Audit Enforcement
    # --------------------------------------------------------------------------

    async def enforce_mutation_audit(
        self,
        action: str,
        actor: Dict[str, Any],
        resource_type: str,
        resource_id: str,
        details: Dict[str, Any],
        tenant_id: str = "global",
    ):
        """
        Mandatory audit enforcement for all state mutations.
        FAIL-CLOSED SECURITY GUARANTEE:
        If the audit ledger raises AuditStorageError or is unavailable,
        the administrative mutation is strictly rejected (503 Service Unavailable).
        Un-audited state changes are never permitted.
        """
        try:
            record = await self.audit_ledger.append_entry(
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                actor=actor,
                tenant_id=tenant_id,
                details=details,
                status="SUCCESS",
            )
            return record
        except AuditStorageError as ase:
            logger.critical(
                f"[MSM] FAIL-CLOSED ENFORCEMENT: Mutation '{action}' rejected due to audit storage failure: {ase}"
            )
            alert = SecurityAlert(
                severity=AlertSeverity.CRITICAL,
                category=AlertCategory.STORAGE_FAILURE,
                source="management_monitor.audit_enforcer",
                message=f"Fail-closed mutation rejection: Audit ledger storage failed during {action}",
                details={"action": action, "resource_id": resource_id, "error": str(ase)},
            )
            await self.broadcast_alert(alert)
            raise FailClosedAuditError(
                f"Administrative operation '{action}' rejected: Audit ledger storage failure (fail-closed mandate)."
            )
        except Exception as e:
            logger.critical(f"[MSM] Unexpected error recording audit: {e}")
            raise FailClosedAuditError(f"Administrative operation rejected: Audit error: {e}")

    # --------------------------------------------------------------------------
    # 4. Dual-Approval (Two-Man Rule) for High-Impact Actions
    # --------------------------------------------------------------------------

    def create_dual_approval_request(
        self,
        action_name: str,
        requester_id: str,
        approver_id: str,
        ttl_seconds: float = 300.0,
        tenant_id: str = "global",
        details: Optional[Dict[str, Any]] = None,
    ) -> DualApprovalRecord:
        """
        Authorizes a high-impact operation using the Two-Man Rule.
        Enforces that requester and approver must be distinct identities.
        """
        if requester_id == approver_id:
            raise ManagementSecurityError(
                "Two-man authorization rule violation: Requester and Approver must be distinct accounts.",
                AdminAnomalyType.DUAL_APPROVAL_MISSING,
                status_code=400,
            )

        token = secrets.token_hex(24)
        now = get_utc_now_timestamp()
        record = DualApprovalRecord(
            action_id=f"act-{secrets.token_hex(6)}",
            action_name=action_name,
            requester_id=requester_id,
            approver_id=approver_id,
            token=token,
            created_at=now,
            expires_at=now + ttl_seconds,
            tenant_id=tenant_id,
            details=details or {},
        )
        self._dual_approval_store[token] = record
        return record

    def verify_and_consume_dual_approval(
        self,
        action_name: str,
        token: Optional[str],
        actor_id: str,
        tenant_id: str = "global",
    ) -> bool:
        """
        Verifies and consumes a one-time dual-approval authorization token.
        Raises DualApprovalRequiredError if missing, expired, or replayed.
        """
        if not token:
            raise DualApprovalRequiredError(
                f"Action '{action_name}' is classified as HIGH-IMPACT and requires dual-approval confirmation ('X-Dual-Approval-Token')."
            )

        record = self._dual_approval_store.get(token)
        if not record:
            raise DualApprovalRequiredError("Invalid or unknown dual-approval token.")

        if record.used:
            raise DualApprovalRequiredError("Dual-approval token has already been consumed (replay prevention).")

        now = get_utc_now_timestamp()
        if now > record.expires_at:
            raise DualApprovalRequiredError("Dual-approval token has expired.")

        if record.action_name != action_name:
            raise DualApprovalRequiredError(
                f"Dual-approval token was issued for '{record.action_name}', not '{action_name}'."
            )

        if record.tenant_id != "global" and record.tenant_id != tenant_id:
            raise DualApprovalRequiredError("Dual-approval token belongs to a different organisation.")

        # Consume token
        record.used = True
        logger.info(
            f"[MSM] Dual approval validated and consumed for '{action_name}' "
            f"(Requested by {record.requester_id}, Approved by {record.approver_id})"
        )
        return True


# Global Singleton Instance
management_monitor = ManagementSecurityMonitor()
