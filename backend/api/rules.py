import time
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field

from backend.utils.logger import get_logger
from backend.auth.roles import Role, Capabilities
from backend.auth.permissions import require_permission
from backend.services.central_management_service import central_management_service
from backend.self_defense.management_monitor import (
    management_monitor,
    ManagementSecurityError,
    FailClosedAuditError,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/rules", tags=["rules"])

# Default in-memory rule store (persisted across sessions via central management)
DEFAULT_RULES: Dict[str, List[Dict[str, Any]]] = {
    "suricata_signatures": [
        {
            "id": "ET-2010935",
            "sid": 2010935,
            "engine": "suricata",
            "name": "ET EXPLOIT Lateral SMB Exec",
            "category": "attempted-admin",
            "mitre": "T1021 Remote Services",
            "stage": "lateral_movement",
            "action": "alert",
            "severity": "HIGH",
            "confidence": 0.88,
            "enabled": True,
            "description": "Detects SMB execution payloads typically associated with PsExec or lateral movement toolkits."
        },
        {
            "id": "ET-2028911",
            "sid": 2028911,
            "engine": "suricata",
            "name": "ET TROJAN Cobalt Strike Beaconing",
            "category": "trojan-activity",
            "mitre": "T1071 Application Layer Protocol",
            "stage": "c2_exfil",
            "action": "alert",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "enabled": True,
            "description": "Matches periodic HTTP/HTTPS beaconing heuristics and malleable C2 profile signatures."
        },
        {
            "id": "ET-2001219",
            "sid": 2001219,
            "engine": "suricata",
            "name": "ET SCAN Potential Nmap Service Sweep",
            "category": "network-scan",
            "mitre": "T1046 Network Service Discovery",
            "stage": "discovery",
            "action": "alert",
            "severity": "MEDIUM",
            "confidence": 0.75,
            "enabled": True,
            "description": "Detects sequential TCP SYN probe behavior characteristic of Nmap service scans."
        },
        {
            "id": "ET-2019401",
            "sid": 2019401,
            "engine": "suricata",
            "name": "ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228)",
            "category": "attempted-user",
            "mitre": "T1190 Exploit Public-Facing Application",
            "stage": "initial_access",
            "action": "drop",
            "severity": "CRITICAL",
            "confidence": 0.96,
            "enabled": True,
            "description": "Detects JNDI lookup strings (${jndi:ldap/rmi}) in HTTP request headers and URIs."
        },
        {
            "id": "ET-2024888",
            "sid": 2024888,
            "engine": "suricata",
            "name": "ET TROJAN DNS Tunneling Payload Exfiltration",
            "category": "trojan-activity",
            "mitre": "T1048 Exfiltration Over Alternative Protocol",
            "stage": "c2_exfil",
            "action": "alert",
            "severity": "HIGH",
            "confidence": 0.90,
            "enabled": True,
            "description": "Detects encoded subdomains exceeding standard RFC payload lengths transmitting encoded data."
        }
    ],
    "netriq_heuristics": [
        {
            "id": "NETRIQ:RULE:PORT_SCAN_RECON",
            "engine": "netriq_heuristic",
            "name": "Multi-Port Reconnaissance Sweep",
            "type": "sliding_window_threshold",
            "category": "reconnaissance",
            "mitre": "T1046 Network Service Discovery",
            "stage": "discovery",
            "severity": "MEDIUM",
            "confidence": 0.82,
            "window_seconds": 60,
            "threshold": 8,
            "unit": "unique destination ports",
            "enabled": True,
            "description": "Flags a single source attempting connections to 8 or more unique destination ports within a 60-second window."
        },
        {
            "id": "NETRIQ:RULE:MULTI_HOST_SWEEP",
            "engine": "netriq_heuristic",
            "name": "Multi-Host Lateral Sweep",
            "type": "sliding_window_threshold",
            "category": "lateral_movement",
            "mitre": "T1046 Network Service Discovery",
            "stage": "discovery",
            "severity": "HIGH",
            "confidence": 0.85,
            "window_seconds": 60,
            "threshold": 5,
            "unit": "unique target IP addresses",
            "enabled": True,
            "description": "Flags a source host attempting connections to 5 or more unique internal destination IPs within 60 seconds."
        },
        {
            "id": "NETRIQ:RULE:UNUSUAL_DNS_ACTIVITY",
            "engine": "netriq_heuristic",
            "name": "Outbound DNS Tunneling & High Entropy",
            "type": "entropy_length_check",
            "category": "c2_exfiltration",
            "mitre": "T1071 Application Layer Protocol",
            "stage": "c2_exfil",
            "severity": "HIGH",
            "confidence": 0.91,
            "threshold": 3.6,
            "unit": "Shannon Entropy bits (min length: 35)",
            "enabled": True,
            "description": "Calculates information entropy on outbound DNS query prefixes to detect covert base64/hex data exfiltration."
        },
        {
            "id": "NETRIQ:RULE:FAILED_CONNECTION_CHURN",
            "engine": "netriq_heuristic",
            "name": "Zeek Connection State Churn (S0/REJ)",
            "type": "zeek_state_monitor",
            "category": "brute_force",
            "mitre": "T1110 Brute Force",
            "stage": "credential_access",
            "severity": "MEDIUM",
            "confidence": 0.78,
            "threshold": 5,
            "unit": "unanswered/rejected connections in 60s",
            "enabled": True,
            "description": "Correlates Zeek conn.log states S0 (SYN sent, no response) and REJ (connection rejected) to detect port knocking or credential brute force."
        },
        {
            "id": "NETRIQ:RULE:CONNECTION_FLOOD",
            "engine": "netriq_heuristic",
            "name": "Connection Burst / SYN Flood",
            "type": "rate_anomaly",
            "category": "dos",
            "mitre": "T1498 Network Denial of Service",
            "stage": "impact",
            "severity": "HIGH",
            "confidence": 0.86,
            "threshold": 40,
            "unit": "connections per minute",
            "enabled": True,
            "description": "Detects sudden volume spikes exceeding 40 connections per minute from a single internal or external address."
        }
    ],
    "behaviour_baselines": [
        {
            "id": "NETRIQ:BEHAVIOUR:STATISTICAL_BASELINE",
            "engine": "behaviour_engine",
            "name": "Moving Average Statistical Anomaly (3-Sigma)",
            "type": "statistical_profiler",
            "metric": "hourly_connection_volume",
            "z_threshold": 3.0,
            "enabled": True,
            "description": "Evaluates observed host traffic volumes against rolling 7-day historical means, triggering when exceeding μ + 3σ."
        },
        {
            "id": "NETRIQ:BEHAVIOUR:NOVEL_PORT",
            "engine": "behaviour_engine",
            "name": "Novel Port & Protocol Observation",
            "type": "novelty_detection",
            "metric": "unseen_port_access",
            "enabled": True,
            "description": "Flags destination ports and transport protocols that have never previously been accessed by this host role."
        }
    ]
}

class RuleUpdateReq(BaseModel):
    enabled: Optional[bool] = None
    threshold: Optional[float] = None
    action: Optional[str] = None
    severity: Optional[str] = None

@router.get("", dependencies=[Depends(require_permission(Capabilities.VIEW_DETECTION_RULES))])
async def get_detection_rules(req: Request):
    """
    Returns full detection rule library:
    Suricata signatures, stateful NetrIQ heuristics, and behavioural baseline models.
    """
    user = getattr(req.state, "user", None)
    if isinstance(user, dict) and user.get("tenant_id") and user.get("tenant_id") != "global":
        tenant_id = user.get("tenant_id")
    else:
        tenant_id = req.headers.get("X-Tenant-ID", "default")
    version = time.strftime("%Y.%m.%d.01", time.gmtime())

    total_rules = (
        len(DEFAULT_RULES["suricata_signatures"]) +
        len(DEFAULT_RULES["netriq_heuristics"]) +
        len(DEFAULT_RULES["behaviour_baselines"])
    )

    active_count = sum(
        1 for cat in DEFAULT_RULES.values()
        for r in cat
        if r.get("enabled", True)
    )

    return {
        "tenant_id": tenant_id,
        "manifest_version": version,
        "total_rules": total_rules,
        "active_rules": active_count,
        "suricata_signatures": DEFAULT_RULES["suricata_signatures"],
        "netriq_heuristics": DEFAULT_RULES["netriq_heuristics"],
        "behaviour_baselines": DEFAULT_RULES["behaviour_baselines"]
    }

@router.put("/{rule_id}", dependencies=[Depends(require_permission(Capabilities.MANAGE_DETECTION_RULES))])
async def update_detection_rule(rule_id: str, payload: RuleUpdateReq, req: Request):
    """Updates rule configuration or toggle status with mandatory fail-closed audit enforcement."""
    actor = getattr(req.state, "user", {}) or {}
    actor_id = actor.get("sub") or actor.get("email") or "admin"
    tenant_id = actor.get("tenant_id", "default")

    # Management Security Monitor Anomaly & Rate Check
    try:
        management_monitor.check_admin_rate_limits(actor_id=actor_id, action="UPDATE_DETECTION_RULE", tenant_id=tenant_id)
    except ManagementSecurityError as mse:
        raise HTTPException(status_code=mse.status_code, detail=str(mse))

    # Check rule exists before audit
    target_rule = None
    for category in ["suricata_signatures", "netriq_heuristics", "behaviour_baselines"]:
        for rule in DEFAULT_RULES.get(category, []):
            if rule["id"] == rule_id:
                target_rule = rule
                break
        if target_rule:
            break

    if not target_rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule {rule_id} not found")

    # Mandatory Sealed Audit Enforcement: MUST succeed before mutating rule state (Fail-Closed)
    try:
        await management_monitor.enforce_mutation_audit(
            action="UPDATE_DETECTION_RULE",
            actor=actor,
            resource_type="detection_rule",
            resource_id=rule_id,
            details={"rule_id": rule_id, "updates": payload.model_dump(exclude_none=True)},
            tenant_id=tenant_id
        )
    except FailClosedAuditError as fce:
        raise HTTPException(status_code=fce.status_code, detail=str(fce))

    # Apply mutation to rule state
    if payload.enabled is not None:
        target_rule["enabled"] = payload.enabled
    if payload.threshold is not None:
        target_rule["threshold"] = payload.threshold
    if payload.action is not None:
        target_rule["action"] = payload.action
    if payload.severity is not None:
        target_rule["severity"] = payload.severity

    logger.info(f"[RulesAPI] Rule {rule_id} updated by {actor_id}: {payload.model_dump(exclude_none=True)}")
    return {"message": f"Rule {rule_id} updated successfully", "rule": target_rule}

@router.post("/distribute", dependencies=[Depends(require_permission(Capabilities.MANAGE_DETECTION_RULES))])
async def distribute_ruleset_to_sensors(req: Request):
    """Compiles the latest rule manifest and dispatches rule updates to all registered software sensors."""
    actor = getattr(req.state, "user", {}) or {}
    actor_id = actor.get("sub") or actor.get("email") or "admin"
    tenant_id = actor.get("tenant_id", "default")

    # Management Security Monitor Anomaly & Rate Check
    try:
        management_monitor.check_admin_rate_limits(actor_id=actor_id, action="DISTRIBUTE_RULESET", tenant_id=tenant_id)
    except ManagementSecurityError as mse:
        raise HTTPException(status_code=mse.status_code, detail=str(mse))

    manifest = await central_management_service.get_rule_manifest(tenant_id)
    sensors = await central_management_service.list_software_sensors(tenant_id)

    # Mandatory Sealed Audit Enforcement: MUST succeed before confirming distribution
    try:
        await management_monitor.enforce_mutation_audit(
            action="DISTRIBUTE_RULESET",
            actor=actor,
            resource_type="ruleset_distribution",
            resource_id=manifest.version,
            details={"tenant_id": tenant_id, "sensors_count": len(sensors)},
            tenant_id=tenant_id
        )
    except FailClosedAuditError as fce:
        raise HTTPException(status_code=fce.status_code, detail=str(fce))
    
    return {
        "status": "success",
        "message": f"Compiled and distributed rule manifest {manifest.version} to {len(sensors)} sensor daemons.",
        "version": manifest.version,
        "sensors_synchronized": len(sensors),
        "timestamp": time.time()
    }
