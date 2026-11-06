"""
backend/intelligence/config.py
Configurable parameters for the NetrIQ Intelligence Pipeline.

Mandate:
NO hardcoded values. All weights, thresholds, window durations, dampening factors,
and port/tool mappings are configurable via environment variables, runtime settings,
or tenant configuration overrides.
"""

import os
import json
from typing import Dict, Any, List, Set, Optional
from pydantic import BaseModel, Field


def _parse_port_map(env_var: str, default: Dict[int, str]) -> Dict[int, str]:
    """Parses port mapping from JSON env var or falls back to default."""
    raw = os.getenv(env_var)
    if raw:
        try:
            parsed = json.loads(raw)
            return {int(k): str(v) for k, v in parsed.items()}
        except Exception:
            pass
    return default


def _parse_str_map(env_var: str, default: Dict[str, str]) -> Dict[str, str]:
    """Parses tool mapping from JSON env var or falls back to default."""
    raw = os.getenv(env_var)
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            pass
    return default


class IntelligenceConfig(BaseModel):
    """
    Master configuration schema for the 6-stage intelligence pipeline.
    All properties load from environment variables with zero hardcoded static constants.
    """

    # --- Signal Weights for Risk Scoring (Max Base = 100) ---
    weight_signature: float = Field(
        default_factory=lambda: float(os.getenv("NETRIQ_INTEL_WEIGHT_SIGNATURE", "30.0")),
        description="Weight for known malicious signatures (e.g. Suricata/Zeek detection)"
    )
    weight_connection_frequency: float = Field(
        default_factory=lambda: float(os.getenv("NETRIQ_INTEL_WEIGHT_FREQ", "20.0")),
        description="Weight for high connection frequency bursts / rate anomalies"
    )
    weight_unusual_destination: float = Field(
        default_factory=lambda: float(os.getenv("NETRIQ_INTEL_WEIGHT_UNUSUAL_DEST", "15.0")),
        description="Weight for targeting an unusual or first-seen destination / crown jewel"
    )
    weight_multiple_events: float = Field(
        default_factory=lambda: float(os.getenv("NETRIQ_INTEL_WEIGHT_EVENTS", "20.0")),
        description="Weight for multi-stage correlated observations across sliding windows"
    )
    weight_behavioural_deviation: float = Field(
        default_factory=lambda: float(os.getenv("NETRIQ_INTEL_WEIGHT_BEHAVIOUR", "15.0")),
        description="Weight for statistical deviations from host baseline"
    )

    # --- Anti-Double-Counting & Dampening Controls ---
    correlation_dampening_factor: float = Field(
        default_factory=lambda: float(os.getenv("NETRIQ_INTEL_DAMPENING", "0.25")),
        description="Subsumption discount factor (alpha) applied to secondary signals within the same causal category"
    )
    max_severity_score: float = Field(
        default_factory=lambda: float(os.getenv("NETRIQ_INTEL_MAX_SEVERITY", "100.0")),
        description="Ceiling for raw calculated severity"
    )

    # --- Temporal Windows & Event Volume Thresholds ---
    window_seconds: float = Field(
        default_factory=lambda: float(os.getenv("NETRIQ_INTEL_WINDOW_SEC", "600.0")),
        description="Sliding correlation window in seconds (default: 10 minutes)"
    )
    port_scan_port_threshold: int = Field(
        default_factory=lambda: int(os.getenv("NETRIQ_INTEL_PORT_THRESHOLD", "8")),
        description="Minimum unique destination ports probed to classify as a port scan"
    )
    port_scan_ip_threshold: int = Field(
        default_factory=lambda: int(os.getenv("NETRIQ_INTEL_IP_THRESHOLD", "5")),
        description="Minimum unique destination IPs probed to classify as a subnet sweep"
    )
    high_freq_connection_threshold: int = Field(
        default_factory=lambda: int(os.getenv("NETRIQ_INTEL_HIGH_FREQ_CONN_THRESHOLD", "15")),
        description="Threshold of connections per minute considered high frequency burst"
    )
    min_observations_for_incident: int = Field(
        default_factory=lambda: int(os.getenv("NETRIQ_INTEL_MIN_OBSERVATIONS", "3")),
        description="Minimum correlated observations to synthesize an active investigation"
    )

    # --- Severity Classification Cutoffs ---
    severity_critical_threshold: float = Field(
        default_factory=lambda: float(os.getenv("NETRIQ_SEVERITY_CRITICAL_CUTOFF", "65.0")),
        description="Score cutoff for CRITICAL severity"
    )
    severity_high_threshold: float = Field(
        default_factory=lambda: float(os.getenv("NETRIQ_SEVERITY_HIGH_CUTOFF", "40.0")),
        description="Score cutoff for HIGH severity"
    )
    severity_medium_threshold: float = Field(
        default_factory=lambda: float(os.getenv("NETRIQ_SEVERITY_MEDIUM_CUTOFF", "20.0")),
        description="Score cutoff for MEDIUM severity"
    )

    # --- Confidence Classification Cutoffs ---
    confidence_confirmed_threshold: float = Field(
        default_factory=lambda: float(os.getenv("NETRIQ_CONFIDENCE_CONFIRMED_CUTOFF", "0.90")),
        description="Certainty cutoff for CONFIRMED label"
    )
    confidence_probable_threshold: float = Field(
        default_factory=lambda: float(os.getenv("NETRIQ_CONFIDENCE_PROBABLE_CUTOFF", "0.75")),
        description="Certainty cutoff for PROBABLE label"
    )
    confidence_suspected_threshold: float = Field(
        default_factory=lambda: float(os.getenv("NETRIQ_CONFIDENCE_SUSPECTED_CUTOFF", "0.60")),
        description="Certainty cutoff for SUSPECTED label"
    )

    # --- Dynamic Port Classifications ---
    lateral_ports: Dict[int, str] = Field(
        default_factory=lambda: _parse_port_map("NETRIQ_LATERAL_PORTS_JSON", {
            445: "SMB / File Sharing",
            135: "RPC Endpoint Mapper",
            139: "NetBIOS Session Service",
            3389: "RDP Remote Desktop",
            22: "SSH Remote Shell",
            5985: "WinRM HTTP",
            5986: "WinRM HTTPS",
            21: "FTP Control",
            23: "Telnet"
        })
    )

    crown_jewel_ports: Dict[int, str] = Field(
        default_factory=lambda: _parse_port_map("NETRIQ_CROWN_JEWEL_PORTS_JSON", {
            1433: "MSSQL Database",
            3306: "MySQL Database",
            5432: "PostgreSQL Database",
            27017: "MongoDB Cluster",
            6379: "Redis In-Memory Store",
            88: "Kerberos Key Distribution",
            389: "LDAP Directory Service",
            636: "LDAPS Secure Directory"
        })
    )

    critical_tools: Dict[str, str] = Field(
        default_factory=lambda: _parse_str_map("NETRIQ_CRITICAL_TOOLS_JSON", {
            "mimikatz.exe": "T1003 OS Credential Dumping",
            "nmap.exe": "T1046 Network Service Discovery",
            "responder.py": "T1557 LLMNR/NBT-NS Poisoning",
            "cobaltstrike": "T1071 Command and Control Beacon",
            "psexec.exe": "T1569 Lateral Tool Execution",
            "hydra.exe": "T1110 Brute Force Password Cracker",
            "wireshark.exe": "T1040 Network Sniffing",
            "chisel.exe": "T1572 Protocol Tunneling / Proxy"
        })
    )


# Singleton default configuration, modifiable at runtime without restarting
intelligence_config = IntelligenceConfig()

