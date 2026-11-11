import os
import asyncio
import ipaddress
import re
import time
from typing import Dict, Any, Optional

from backend.ai.contracts import Action, PredictionResult
from backend.utils.logger import get_logger
from backend.response.firewall import get_firewall_adapter
from backend.response.quarantine import QuarantineService
from backend.response.whitelist import WhitelistManager
from backend.response.response_logger import ResponseLogger
from backend.response.exceptions import EnforcementAlreadyActiveError
from backend.pipeline.identity_resolver import identity_resolver

logger = get_logger(__name__)

QUARANTINE_MAX_QUOTA_PER_HOUR = int(os.getenv("QUARANTINE_MAX_QUOTA_PER_HOUR", "10"))
DEFAULT_QUARANTINE_EXPIRY_SECONDS = int(os.getenv("QUARANTINE_EXPIRY_SECONDS", "3600"))

_MAC_REGEX = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$")


class ResponseEngine:
    """
    Single dispatch point for all enforcement actions based on AI verdicts.
    Strictly adheres to Layer 1 (Firewall) vs Layer 2 (Quarantine) separation.
    
    Safety Controls:
    1. Passive Detection Posture (defaults to guided analyst review unless auto_quarantine is explicitly enabled).
    2. CIDR-aware Infrastructure Protection (Gateways, Loopbacks, Multicast, Broadcast, RFC1918 boundaries).
    3. Crown Jewel Asset Protection (prevents accidental isolation of critical servers, DNS, AD).
    4. Quarantine Quota Limiting (caps automated quarantines within a sliding window to prevent cascading DoS).
    5. Automatic Rollback / Expiry metadata tracking.
    """
    def __init__(self):
        self.firewall = get_firewall_adapter()
        self.quarantine = QuarantineService()
        self.whitelist = WhitelistManager()
        self.logger = ResponseLogger()
        self._recent_quarantines: Dict[str, float] = {}
        self._max_quarantine_quota = int(os.getenv("QUARANTINE_MAX_QUOTA_PER_HOUR", "10"))

    @property
    def max_quarantine_quota(self) -> int:
        return self._max_quarantine_quota

    @max_quarantine_quota.setter
    def max_quarantine_quota(self, val: int):
        self._max_quarantine_quota = val

    def _is_valid_ip(self, ip_str: str) -> bool:
        if not ip_str or ip_str == "unknown":
            return False
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    def _is_valid_mac(self, mac_str: Optional[str]) -> bool:
        """
        Validates whether mac_str is a plausible, verified unicast 6-octet MAC address.
        Strictly rejects broadcast (FF:FF:FF:FF:FF:FF), all-zeros (00:00:00:00:00:00),
        multicast, incomplete octets, or unformatted strings.
        """
        if not mac_str or not isinstance(mac_str, str):
            return False
        cleaned = mac_str.strip().lower()
        if cleaned in ("unknown", "none", "null", "undefined"):
            return False
        if cleaned in ("00:00:00:00:00:00", "00-00-00-00-00-00"):
            return False
        if cleaned in ("ff:ff:ff:ff:ff:ff", "ff-ff-ff-ff-ff-ff"):
            return False
        if cleaned.startswith("01:00:5e") or cleaned.startswith("33:33"):
            return False

        if not _MAC_REGEX.match(cleaned):
            return False

        parts = cleaned.replace("-", ":").split(":")
        if len(parts) != 6:
            return False
        try:
            # Check individual/group (multicast) bit on first octet
            if int(parts[0], 16) & 1 == 1:
                return False
        except ValueError:
            return False
        return True

    async def _verify_enforcement_active(self, adapter: Any, target_ip: str) -> bool:
        """
        Independently queries the adapter's state to verify the target IP is actively enforced.
        """
        if hasattr(adapter, "is_blocked"):
            try:
                res = adapter.is_blocked(target_ip)
                if asyncio.iscoroutine(res):
                    return await res
                return bool(res)
            except Exception:
                pass
        elif hasattr(adapter, "is_quarantined"):
            try:
                res = adapter.is_quarantined(target_ip)
                if asyncio.iscoroutine(res):
                    return await res
                return bool(res)
            except Exception:
                pass
        return False

    async def _is_idempotent_success(self, exc: Exception, adapter: Any, target_ip: str) -> bool:
        """
        Strictly verifies if an enforcement error corresponds to an already-enforced state.
        Requires either typed EnforcementAlreadyActiveError, HTTP 409 Conflict,
        or an explicit target-bound enforcement message confirmed by adapter state check.
        """
        if isinstance(exc, EnforcementAlreadyActiveError):
            return True

        is_http_409 = hasattr(exc, "response") and getattr(exc.response, "status_code", None) == 409
        msg = str(exc).lower()
        has_specific_msg = any(
            phrase in msg for phrase in [
                f"ip {target_ip} is already blocked",
                f"device {target_ip} is already quarantined",
                f"rule already exists for {target_ip}",
                "already in isolation"
            ]
        )

        if is_http_409 or has_specific_msg:
            if hasattr(adapter, "is_blocked") or hasattr(adapter, "is_quarantined"):
                is_active = await self._verify_enforcement_active(adapter, target_ip)
                if not is_active:
                    logger.warning(
                        f"[ResponseEngine] Adapter returned conflict for {target_ip}, "
                        "but independent state check could not confirm active enforcement."
                    )
                    return False
            return True

        return False

    async def _execute_with_retry(
        self,
        func,
        *args,
        max_retries: int = 2,
        initial_delay: float = 0.1,
        adapter: Any = None,
        **kwargs
    ) -> bool:
        """
        Executes a response enforcement call with automatic retries and typed idempotency checks.
        Handles ambiguous timeouts by verifying when target state is already actively enforced.
        """
        last_exc = None
        target_ip = args[0] if args else kwargs.get("ip_address", "")

        for attempt in range(max_retries + 1):
            try:
                res = await func(*args, **kwargs)
                if res:
                    return True
                if attempt < max_retries:
                    logger.warning(
                        f"[ResponseEngine] Response action returned False (attempt {attempt + 1}/{max_retries + 1}). Retrying in {initial_delay}s..."
                    )
                    await asyncio.sleep(initial_delay)
            except Exception as e:
                # Typed and verified idempotency check
                if await self._is_idempotent_success(e, adapter, str(target_ip)):
                    logger.info(f"[ResponseEngine] Idempotent success verified for {target_ip}: target already actively enforced.")
                    return True

                last_exc = e
                if attempt < max_retries:
                    logger.warning(
                        f"[ResponseEngine] Response action failed with {type(e).__name__:s}: {e} (attempt {attempt + 1}/{max_retries + 1}). Retrying in {initial_delay}s..."
                    )
                    await asyncio.sleep(initial_delay)
                else:
                    logger.error(
                        f"[ResponseEngine] Response action failed after {max_retries + 1} attempts: {e}"
                    )
                    raise last_exc
        return False

    def _is_protected_infrastructure(self, target_ip: str, context: Dict[str, Any]) -> tuple[bool, str]:
        """
        Validates target IP against CIDR-aware infrastructure boundaries:
        1. Special IP ranges (loopback, link-local, multicast, broadcast, unspecified).
        2. Configured or detected gateway addresses.
        3. Subnet network (.0) and broadcast (.255) boundaries based on CIDR math.
        4. Tenant crown jewel assets and critical server inventory.
        """
        try:
            addr = ipaddress.ip_address(target_ip)
        except ValueError:
            return True, "Invalid IP"

        # 1. Special RFC ranges
        if addr.is_loopback:
            return True, "Loopback Interface"
        if addr.is_multicast:
            return True, "Multicast Group"
        if addr.is_link_local:
            return True, "Link-Local Address"
        if addr.is_unspecified or addr == ipaddress.ip_address("255.255.255.255"):
            return True, "Unspecified/Broadcast IP"

        # 2. Configured Crown Jewel Assets
        env_jewels = [ip.strip() for ip in os.getenv("CROWN_JEWEL_ASSETS", "").split(",") if ip.strip()]
        context_jewels = context.get("crown_jewel_assets") or []
        if isinstance(context_jewels, list):
            crown_jewels = set(env_jewels + context_jewels)
        else:
            crown_jewels = set(env_jewels)

        if target_ip in crown_jewels:
            return True, "Crown Jewel Asset"

        # 3. Protected Gateways
        env_gateways = [ip.strip() for ip in os.getenv("PROTECTED_GATEWAYS", "").split(",") if ip.strip()]
        if target_ip in env_gateways:
            return True, "Protected Gateway"

        # 4. CIDR subnet checks for network, broadcast, and standard gateway offsets
        subnets_raw = os.getenv("INTERNAL_SUBNETS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
        subnet_strs = [s.strip() for s in subnets_raw.split(",") if s.strip()]

        for s_str in subnet_strs:
            try:
                net = ipaddress.ip_network(s_str, strict=False)
                if addr in net:
                    if addr == net.network_address:
                        return True, "Subnet Network Address"
                    if addr == net.broadcast_address:
                        return True, "Subnet Broadcast Address"
            except ValueError:
                continue

        # Heuristic for standard /24 edge gateways (e.g. 192.168.X.1 or 192.168.X.254)
        if addr.is_private:
            last_octet = str(target_ip).split(".")[-1] if "." in str(target_ip) else ""
            if last_octet in ("1", "254"):
                return True, "Standard Subnet Gateway"

        return False, ""

    def _check_quarantine_quota(self, target_ip: str) -> bool:
        """Enforces sliding-window maximum quarantine quota to prevent DoS."""
        now = time.time()
        self._recent_quarantines = {ip: ts for ip, ts in self._recent_quarantines.items() if now - ts < 3600}
        if target_ip in self._recent_quarantines:
            return True
        if len(self._recent_quarantines) >= self.max_quarantine_quota:
            return False
        return True

    def _record_quarantine_success(self, target_ip: str):
        self._recent_quarantines[target_ip] = time.time()

    async def handle_verdict(self, prediction: PredictionResult, action: Action, context: Dict[str, Any]) -> bool:
        """
        Dispatches action based on the Action enum.
        Includes try/except blocks per action so downstream failures do not crash the pipeline.
        """
        target_ip = context.get("src_ip", "unknown")
        target_mac = context.get("src_mac")
        reason = f"AI Verdict: {prediction.model_used} - Confidence: {prediction.confidence:.2f}%"

        # Validate IP before enforcement if action requires blocking/quarantining
        if action in (Action.RECOMMEND_BLOCK, Action.QUARANTINE) and not self._is_valid_ip(target_ip):
            logger.warning(f"Aborting response action {action.name}: Invalid or missing target IP '{target_ip}'")
            await self.logger.log_action(action, target_ip, "Aborted (Invalid IP)", False, context)
            return False

        # Protect core network infrastructure (Gateway, Loopback, Broadcast, Crown Jewels)
        is_protected, protect_reason = self._is_protected_infrastructure(target_ip, context)
        if is_protected:
            logger.info(f"Target {target_ip} is protected core network infrastructure ({protect_reason}). Bypassing enforcement action: {action.name}")
            await self.logger.log_action(action, target_ip, f"Bypassed (Core Infrastructure: {protect_reason})", True, context)
            return True

        # 1. Whitelist Check (Before Enforcement)
        if await self.whitelist.is_whitelisted(target_ip, target_mac):
            logger.info(f"Target {target_ip} is whitelisted. Bypassing response action: {action.name}")
            await self.logger.log_action(action, target_ip, "Bypassed (Whitelisted)", True, context)
            return True

        # Check Autonomous Response Controller (ARC) Safe Mode / Block Suspension
        blocks_suspended = False
        try:
            from backend.self_defense.response_controller import response_controller
            blocks_suspended = response_controller.are_automated_blocks_suspended()
        except Exception:
            blocks_suspended = False

        if action in (Action.RECOMMEND_BLOCK, Action.QUARANTINE) and blocks_suspended:
            logger.warning(
                f"[ARC SafeMode] Automated enforcement SUSPENDED for {target_ip} due to active Safe Detection Mode. "
                f"Downgrading {action.name} to guided analyst review."
            )
            outcome_msg = f"Safe Mode (Automated Block Suspended - {action.name})"
            await self.logger.log_action(action, target_ip, outcome_msg, True, context)
            asyncio.create_task(self._notify_incident_service(target_ip, prediction, action, False))
            return True

        # Check Passive Detection Posture (auto_quarantine setting)
        auto_quarantine_enabled = False
        try:
            from backend.services.settings_service import settings_service
            current_settings = await settings_service.get_settings()
            auto_quarantine_enabled = current_settings.get("auto_quarantine", False)
        except Exception:
            auto_quarantine_enabled = False

        if action in (Action.RECOMMEND_BLOCK, Action.QUARANTINE) and not auto_quarantine_enabled:
            logger.info(f"[PassiveMode] Automated enforcement disabled ('auto_quarantine'=False). Downgrading {action.name} to guided analyst review for {target_ip}.")
            outcome_msg = f"Passive Mode (Guided Review - {action.name})"
            await self.logger.log_action(action, target_ip, outcome_msg, True, context)
            asyncio.create_task(self._notify_incident_service(target_ip, prediction, action, False))
            return True

        # Validate MAC identity before Layer 2 quarantine to prevent IP spoofing & switch port isolation
        if action == Action.QUARANTINE:
            resolved_device = identity_resolver.resolve(ip=target_ip)
            has_valid_mac = self._is_valid_mac(target_mac)

            if not has_valid_mac:
                # Attempt to resolve authoritative MAC from identity resolver
                if resolved_device and resolved_device.mac and self._is_valid_mac(resolved_device.mac):
                    target_mac = resolved_device.mac
                    logger.info(f"[ResponseEngine] Resolved authoritative MAC {target_mac} for target {target_ip} via IdentityResolver.")
                else:
                    logger.critical(
                        f"[ResponseEngine] Suppressing Layer 2 quarantine for {target_ip}: "
                        f"unverified or missing MAC address ('{target_mac}'). "
                        "Preventing potential IP spoofing / switch port isolation."
                    )
                    await self.logger.log_action(
                        action, target_ip, "Layer 2 MAC Unverified (Suppressed)", False, context
                    )
                    return False
            else:
                # Syntactically valid MAC supplied: independently verify against authoritative IdentityResolver
                if resolved_device and resolved_device.is_managed and resolved_device.mac:
                    cleaned_supplied = target_mac.strip().replace("-", ":").upper()
                    cleaned_auth = resolved_device.mac.strip().replace("-", ":").upper()
                    if cleaned_supplied != cleaned_auth:
                        logger.critical(
                            f"[ResponseEngine] MAC spoofing detected for {target_ip}! "
                            f"Supplied MAC '{target_mac}' contradicts authoritative registered MAC '{resolved_device.mac}'. "
                            "Suppressing quarantine to prevent isolating spoofed network host."
                        )
                        await self.logger.log_action(
                            action, target_ip, "Layer 2 MAC Spoofing Mismatch (Suppressed)", False, context
                        )
                        return False

        # Check quarantine quota before executing Layer 2 quarantine
        if action == Action.QUARANTINE and not self._check_quarantine_quota(target_ip):
            logger.critical(f"[ResponseEngine] Quarantine quota limit ({QUARANTINE_MAX_QUOTA_PER_HOUR}/hr) exceeded. Suppressing automatic quarantine for {target_ip} to prevent network denial-of-service.")
            await self.logger.log_action(action, target_ip, "Bypassed (Quarantine Quota Exceeded)", False, context)
            return False

        success = False
        outcome_msg = ""

        try:
            # 2. Dispatch based on strict architecture constraints
            if action == Action.NOTIFY:
                logger.info(f"Notification triggered for {target_ip}. No blocking action taken.")
                outcome_msg = "Notification Sent"
                success = True

            elif action == Action.RECOMMEND_BLOCK:
                logger.info(f"Layer 1 action initiated: Recommending Firewall block for {target_ip}")
                try:
                    success = await self._execute_with_retry(self.firewall.block_ip, target_ip, reason, adapter=self.firewall)
                    outcome_msg = "Firewall Blocked" if success else "Firewall Block Failed"
                except Exception as e:
                    logger.error(f"Firewall adapter failure during RECOMMEND_BLOCK: {e}")
                    outcome_msg = "Firewall API Error"
                    success = False

            elif action == Action.QUARANTINE:
                logger.warning(f"Layer 2 action initiated: Triggering Quarantine for internal threat {target_ip}")
                try:
                    success = await self._execute_with_retry(self.quarantine.quarantine_device, target_ip, target_mac, reason, adapter=self.quarantine)
                    if success:
                        self._record_quarantine_success(target_ip)
                        outcome_msg = f"Quarantined (Auto-Expires in {DEFAULT_QUARANTINE_EXPIRY_SECONDS}s)"
                    else:
                        outcome_msg = "Quarantine Failed"
                except Exception as e:
                    logger.error(f"Quarantine service failure during QUARANTINE: {e}")
                    outcome_msg = "Quarantine Service Error"
                    success = False
            else:
                logger.warning(f"Unknown action type: {action}")
                outcome_msg = "Unknown Action"
                success = False

        except Exception as e:
            logger.critical(f"Unexpected failure in response dispatch for {target_ip}: {e}")
            outcome_msg = "Internal Dispatch Error"
            success = False

        # 3. Log Audit Trail
        await self.logger.log_action(action, target_ip, outcome_msg, success, context)

        # 4. Trigger Incident Service for high-impact events
        is_critical_event = (action == Action.QUARANTINE) or (getattr(prediction, 'risk_category', None) and getattr(prediction.risk_category, 'value', '') == 'CRITICAL')
        if is_critical_event:
            asyncio.create_task(self._notify_incident_service(target_ip, prediction, action, success))

        return success

    async def _notify_incident_service(self, target_ip: str, prediction: PredictionResult, action: Action, success: bool):
        try:
            from backend.services.incident_service import incident_service
            await incident_service.create_from_response_action(target_ip, prediction, action, success)
        except Exception as e:
            logger.error(f"[ResponseEngine] Failed to create incident record for {target_ip}: {e}")

    async def reverse_action(self, action: Action, target_ip: str, target_mac: Optional[str] = None) -> bool:
        success = False
        outcome_msg = ""

        try:
            if action == Action.RECOMMEND_BLOCK:
                success = await self.firewall.unblock_ip(target_ip)
                outcome_msg = "Firewall Unblocked"
            elif action == Action.QUARANTINE:
                success = await self.quarantine.release_device(target_ip, target_mac)
                if success and target_ip in self._recent_quarantines:
                    del self._recent_quarantines[target_ip]
                outcome_msg = "Quarantine Released"
            else:
                logger.warning(f"Action {action.name} cannot be reversed.")
                return False
        except Exception as e:
            logger.error(f"Failed to reverse action {action.name} for {target_ip}: {e}")
            outcome_msg = "Reversal Failed"
            success = False

        await self.logger.log_action(action, target_ip, outcome_msg, success, {"reversal": True})
        return success

    async def close(self):
        for target in (self.firewall, self.quarantine):
            if hasattr(target, "close"):
                try:
                    await target.close()
                except Exception:
                    pass
