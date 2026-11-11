"""
backend/self_defense/intelligence_guard.py

Intelligence Integrity Guard (IIG) for NetrIQ Stage 2 Self-Defense.
Implements:
1. Asymmetric cryptographic release manifest verification (Ed25519).
2. Pre-deserialization file hash verification for ML models, metadata, scalers, and vectorizers.
3. Calibrated runtime risk threshold protection against in-memory tampering.
4. Hardened Suricata YAML and detection rule configuration validation.
5. Autonomous Safe Detection Mode (disables untrusted ML inference while keeping deterministic engines operational).
6. Integration with Independent Security Watchdog for periodic integrity sweeps.
"""

import os
import sys
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, Union, Tuple, List

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from backend.utils.logger import get_logger
from backend.self_defense.schemas import (
    IntelligenceManifest,
    AssetManifestEntry,
    AssetIntegrityType,
    IntelligenceAnomalyType,
    IntelligenceIntegrityVerdict,
    SecurityAlert,
    AlertSeverity,
    AlertCategory,
    get_utc_now_timestamp,
    get_utc_now_iso,
)

logger = get_logger(__name__)

# Default Pinned Release Public Key for NetrIQ v1.1 Release Verification
# In production, this can be overridden via NETRIQ_INTEGRITY_PUBLIC_KEY
_DEFAULT_PINNED_PUBLIC_KEY_HEX = (
    "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"  # Pinned release public key
)
PINNED_PUBLIC_KEY_HEX = os.getenv("NETRIQ_INTEGRITY_PUBLIC_KEY", _DEFAULT_PINNED_PUBLIC_KEY_HEX)


# ==============================================================================
# Exceptions
# ==============================================================================

class IntelligenceIntegrityError(Exception):
    """Base class for all intelligence integrity violations."""
    def __init__(self, message: str, anomaly_type: IntelligenceAnomalyType):
        super().__init__(message)
        self.anomaly_type = anomaly_type


class ManifestSignatureVerificationError(IntelligenceIntegrityError):
    def __init__(self, message: str = "Release manifest signature verification failed: unsigned, forged, or corrupt."):
        super().__init__(message, IntelligenceAnomalyType.INVALID_MANIFEST_SIGNATURE)


class AssetIntegrityError(IntelligenceIntegrityError):
    def __init__(self, message: str = "Asset cryptographic hash mismatch: model or configuration altered."):
        super().__init__(message, IntelligenceAnomalyType.HASH_MISMATCH)


class ThresholdTamperingError(IntelligenceIntegrityError):
    def __init__(self, message: str = "Runtime risk threshold tampering detected: calibrated boundary modified."):
        super().__init__(message, IntelligenceAnomalyType.THRESHOLD_MISMATCH)


class RuleTamperingError(IntelligenceIntegrityError):
    def __init__(self, message: str = "Detection rule tampering detected: rule definition altered without authorization."):
        super().__init__(message, IntelligenceAnomalyType.UNAUTHORIZED_RULE_CHANGE)


class SafeModeActiveError(IntelligenceIntegrityError):
    def __init__(self, message: str = "ML inference blocked: Safe Detection Mode is active due to an integrity violation."):
        super().__init__(message, IntelligenceAnomalyType.DESERIALIZATION_BLOCKED)


# ==============================================================================
# Cryptographic & Hash Utilities
# ==============================================================================

def generate_release_keypair() -> Tuple[str, str]:
    """Generates a new Ed25519 keypair for release signing. (private_hex, public_hex)"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    priv_hex = private_key.private_bytes_raw().hex()
    pub_hex = public_key.public_bytes_raw().hex()
    return priv_hex, pub_hex


def canonical_manifest_bytes(manifest_dict: Dict[str, Any]) -> bytes:
    """Returns canonical JSON bytes of manifest excluding signature for deterministic signing."""
    clean = {k: v for k, v in manifest_dict.items() if k != "signature"}
    return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest_payload(manifest_dict: Dict[str, Any], private_key_hex_or_obj: Union[str, ed25519.Ed25519PrivateKey]) -> str:
    """Signs canonical manifest bytes using Ed25519 private key and returns signature hex."""
    if isinstance(private_key_hex_or_obj, str):
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex_or_obj))
    else:
        priv_key = private_key_hex_or_obj
    canon = canonical_manifest_bytes(manifest_dict)
    sig_bytes = priv_key.sign(canon)
    return sig_bytes.hex()


def verify_manifest_signature(manifest_dict: Dict[str, Any], public_key_hex_or_obj: Union[str, ed25519.Ed25519PublicKey]) -> bool:
    """Verifies manifest Ed25519 signature."""
    sig_hex = manifest_dict.get("signature")
    if not sig_hex:
        return False
    if isinstance(public_key_hex_or_obj, str):
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex_or_obj))
    else:
        pub_key = public_key_hex_or_obj

    canon = canonical_manifest_bytes(manifest_dict)
    try:
        pub_key.verify(bytes.fromhex(sig_hex), canon)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def hash_file_sha256(file_path: Union[str, Path]) -> str:
    """Computes SHA-256 hash of a file on disk."""
    p = Path(file_path)
    if not p.is_file():
        raise FileNotFoundError(f"Asset file not found on disk: {file_path}")
    hasher = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


# ==============================================================================
# Intelligence Integrity Guard Engine
# ==============================================================================

class IntelligenceIntegrityGuard:
    """
    Intelligence Integrity Guard (IIG).
    Protects models, metadata, scalers, rules, and risk thresholds.
    Enforces pre-deserialization verification and routes failures to Safe Detection Mode.
    """

    def __init__(
        self,
        manifest_path: Optional[Union[str, Path]] = None,
        public_key_hex: Optional[str] = None,
        project_root: Optional[Union[str, Path]] = None,
    ):
        self.public_key_hex = public_key_hex or PINNED_PUBLIC_KEY_HEX
        self.project_root = Path(project_root) if project_root else Path(__file__).resolve().parent.parent.parent
        self.manifest_path = Path(manifest_path) if manifest_path else self.project_root / "config" / "intelligence_manifest.json"
        
        self.manifest: Optional[IntelligenceManifest] = None
        self.safe_mode_active: bool = False
        self.safe_mode_reason: Optional[str] = None
        self.last_verdict: Optional[IntelligenceIntegrityVerdict] = None

    def activate_safe_mode(self, reason: str, anomaly_type: IntelligenceAnomalyType = IntelligenceAnomalyType.HASH_MISMATCH):
        """
        Activates Safe Detection Mode:
        - Refuses ML model deserialization and inference.
        - Preserves deterministic signature, rule, and behaviour engines.
        - Records critical tamper alert.
        """
        self.safe_mode_active = True
        self.safe_mode_reason = reason
        logger.critical(
            f"[IntelligenceGuard] SAFE DETECTION MODE ACTIVATED: {reason} "
            "(Deterministic signature/rule/behaviour detection remains OPERATIONAL)"
        )

    def deactivate_safe_mode_for_test(self):
        """Helper for test state cleanup."""
        self.safe_mode_active = False
        self.safe_mode_reason = None
        self.manifest = None
        self.last_verdict = None

    def is_safe_mode_active(self) -> bool:
        """Returns True if Safe Detection Mode is active."""
        return self.safe_mode_active

    def load_and_verify_manifest(self, manifest_input: Optional[Union[Dict[str, Any], IntelligenceManifest, str, Path]] = None) -> IntelligenceManifest:
        """
        Loads and verifies the signed release manifest using the pinned public key.
        Raises ManifestSignatureVerificationError if unsigned or forged.
        """
        if manifest_input is None:
            manifest_file = self.manifest_path
            if not manifest_file.exists():
                env = os.getenv("ENVIRONMENT", os.getenv("ENV", "development")).lower()
                if env in ("production", "prod"):
                    self.activate_safe_mode("Missing intelligence manifest in production mode.")
                    raise ManifestSignatureVerificationError(f"Production manifest missing at {manifest_file}")
                # In development mode without manifest, create baseline
                logger.warning(f"[IntelligenceGuard] No manifest file found at {manifest_file}. Safe baseline mode.")
                return None
            with open(manifest_file, "r", encoding="utf-8") as f:
                raw_dict = json.load(f)
        elif isinstance(manifest_input, (str, Path)):
            with open(manifest_input, "r", encoding="utf-8") as f:
                raw_dict = json.load(f)
        elif isinstance(manifest_input, dict):
            raw_dict = manifest_input
        elif isinstance(manifest_input, IntelligenceManifest):
            raw_dict = manifest_input.model_dump()
        else:
            raise ValueError(f"Unsupported manifest input: {type(manifest_input)}")

        # Verify signature
        if not raw_dict.get("signature"):
            self.activate_safe_mode("Manifest is unsigned.")
            raise ManifestSignatureVerificationError("Manifest has no cryptographic signature.")

        is_valid_sig = verify_manifest_signature(raw_dict, self.public_key_hex)
        if not is_valid_sig:
            self.activate_safe_mode("Manifest cryptographic signature verification failed.")
            raise ManifestSignatureVerificationError("Manifest signature mismatch or forged public key.")

        self.manifest = IntelligenceManifest(**raw_dict)
        return self.manifest

    def verify_file_before_deserialization(self, relative_path: str, absolute_path: Union[str, Path]) -> bool:
        """
        CRITICAL SECURITY CHECK:
        Verifies expected SHA-256 hash BEFORE joblib.load() / pickle.load() executes.
        If hash differs or file is unverified:
        - DOES NOT load the file.
        - Activates Safe Detection Mode.
        - Raises AssetIntegrityError.
        """
        if self.safe_mode_active:
            raise SafeModeActiveError(f"Cannot load asset '{relative_path}': {self.safe_mode_reason}")

        if not self.manifest:
            try:
                self.load_and_verify_manifest()
            except ManifestSignatureVerificationError as e:
                self.activate_safe_mode(f"Manifest verification failed before loading {relative_path}: {e}")
                raise

        if not self.manifest:
            # Development fallback without manifest: proceed with warning if not in prod
            env = os.getenv("ENVIRONMENT", os.getenv("ENV", "development")).lower()
            if env in ("production", "prod"):
                self.activate_safe_mode(f"Production requires verified manifest to load {relative_path}.")
                raise AssetIntegrityError(f"Missing manifest for {relative_path} in production.")
            return True

        # Check manifest assets
        entry = self.manifest.assets.get(relative_path)
        if not entry:
            msg = f"Asset '{relative_path}' is not registered in the signed release manifest."
            self.activate_safe_mode(msg)
            raise AssetIntegrityError(msg)

        # Compute hash on disk
        actual_hash = hash_file_sha256(absolute_path)
        if actual_hash.lower() != entry.sha256.lower():
            msg = (
                f"TAMPERING DETECTED for '{relative_path}'! "
                f"Expected SHA-256={entry.sha256}, Actual={actual_hash}. "
                "Refusing to deserialize compromised model binary."
            )
            self.activate_safe_mode(msg)
            logger.critical(f"[IntelligenceGuard] {msg}")
            raise AssetIntegrityError(msg)

        return True

    def verify_runtime_thresholds(self, manifest: Optional[IntelligenceManifest] = None) -> bool:
        """
        Compares active in-memory / environment thresholds against the signed manifest baseline.
        Detects silent tampering that attempts to mute alerts by raising thresholds.
        """
        m = manifest or self.manifest
        if not m or not m.thresholds:
            return True

        from backend.config.config import (
            RISK_THRESHOLDS,
            ACTIONABLE_RISK_THRESHOLD,
            HIGH_ANOMALY_THRESHOLD,
            HEURISTIC_CONFIDENCE_FLOOR,
            HEURISTIC_PACKET_RATE_THRESHOLD,
        )

        current_thresholds = {
            "RISK_LOW_MAX": float(RISK_THRESHOLDS.get("LOW_MAX", 40.0)),
            "RISK_MEDIUM_MAX": float(RISK_THRESHOLDS.get("MEDIUM_MAX", 70.0)),
            "RISK_HIGH_MAX": float(RISK_THRESHOLDS.get("HIGH_MAX", 90.0)),
            "ACTIONABLE_RISK_THRESHOLD": float(ACTIONABLE_RISK_THRESHOLD),
            "HIGH_ANOMALY_THRESHOLD": float(HIGH_ANOMALY_THRESHOLD),
            "HEURISTIC_CONFIDENCE_FLOOR": float(HEURISTIC_CONFIDENCE_FLOOR),
            "HEURISTIC_PACKET_RATE_THRESHOLD": float(HEURISTIC_PACKET_RATE_THRESHOLD),
        }

        mismatches = []
        for key, expected_val in m.thresholds.items():
            actual_val = current_thresholds.get(key)
            if actual_val is None or abs(actual_val - expected_val) > 1e-5:
                mismatches.append(f"{key}: expected {expected_val}, found {actual_val}")

        if mismatches:
            msg = f"Runtime threshold tampering detected! Discrepancies: {'; '.join(mismatches)}"
            self.activate_safe_mode(msg, IntelligenceAnomalyType.THRESHOLD_MISMATCH)
            raise ThresholdTamperingError(msg)

        return True

    def verify_suricata_config(self, config_path: Optional[Union[str, Path]] = None) -> bool:
        """Verifies the integrity of sensor/security/suricata_hardened.yaml against the manifest."""
        if not self.manifest:
            return True
        entry = self.manifest.assets.get("suricata_hardened.yaml")
        if not entry:
            return True

        target_file = Path(config_path) if config_path else self.project_root / "sensor" / "security" / "suricata_hardened.yaml"
        actual_hash = hash_file_sha256(target_file)
        if actual_hash.lower() != entry.sha256.lower():
            msg = f"Suricata configuration tampering detected! Expected {entry.sha256}, got {actual_hash}"
            self.activate_safe_mode(msg, IntelligenceAnomalyType.HASH_MISMATCH)
            raise AssetIntegrityError(msg)
        return True

    def verify_rules(self, rules_dict: Optional[Dict[str, Any]] = None) -> bool:
        """Verifies detection rules configuration hash against the signed manifest."""
        if not self.manifest or not self.manifest.rule_hashes:
            return True

        from backend.api.rules import DEFAULT_RULES
        target_rules = rules_dict if rules_dict is not None else DEFAULT_RULES

        for rule_category, expected_hash in self.manifest.rule_hashes.items():
            if rule_category in target_rules:
                cat_json = json.dumps(target_rules[rule_category], sort_keys=True).encode("utf-8")
                actual_hash = hashlib.sha256(cat_json).hexdigest()
                if actual_hash.lower() != expected_hash.lower():
                    msg = f"Unauthorized detection rule alteration in '{rule_category}'!"
                    self.activate_safe_mode(msg, IntelligenceAnomalyType.UNAUTHORIZED_RULE_CHANGE)
                    raise RuleTamperingError(msg)
        return True

    async def run_integrity_sweep(self) -> IntelligenceIntegrityVerdict:
        """
        Executes a comprehensive periodic integrity verification sweep across all intelligence assets:
        1. Manifest signature check.
        2. Model, scaler, and metadata disk hash check.
        3. Suricata YAML configuration check.
        4. Runtime risk thresholds check.
        5. Detection rule baseline check.
        """
        checked_at = get_utc_now_timestamp()
        checked_at_iso = get_utc_now_iso()
        failed_assets = []
        anomalies = []
        verified_count = 0

        # Step 1: Manifest Check
        try:
            if not self.manifest:
                self.load_and_verify_manifest()
        except ManifestSignatureVerificationError as e:
            anomalies.append({"type": IntelligenceAnomalyType.INVALID_MANIFEST_SIGNATURE.value, "error": str(e)})
            self.last_verdict = IntelligenceIntegrityVerdict(
                is_valid=False,
                safe_mode_active=True,
                verified_assets_count=0,
                failed_assets=["manifest"],
                anomalies=anomalies,
                error_message=str(e),
                checked_at=checked_at,
                checked_at_iso=checked_at_iso,
            )
            return self.last_verdict

        if not self.manifest:
            # Development mode without manifest
            return IntelligenceIntegrityVerdict(
                is_valid=True,
                safe_mode_active=False,
                verified_assets_count=0,
                checked_at=checked_at,
                checked_at_iso=checked_at_iso,
            )

        # Step 2: Check Asset Hashes on Disk
        models_dir = self.project_root / "models"
        sensor_dir = self.project_root / "sensor" / "security"

        for rel_path, entry in self.manifest.assets.items():
            if entry.asset_type == AssetIntegrityType.SURICATA_YAML:
                abs_path = sensor_dir / rel_path
            else:
                abs_path = models_dir / rel_path

            if not abs_path.is_file():
                if entry.critical:
                    failed_assets.append(rel_path)
                    anomalies.append({
                        "asset": rel_path,
                        "type": IntelligenceAnomalyType.MISSING_ASSET.value,
                        "error": f"Missing critical asset: {abs_path}"
                    })
                continue

            try:
                actual_hash = hash_file_sha256(abs_path)
                if actual_hash.lower() != entry.sha256.lower():
                    failed_assets.append(rel_path)
                    anomalies.append({
                        "asset": rel_path,
                        "type": IntelligenceAnomalyType.HASH_MISMATCH.value,
                        "expected": entry.sha256,
                        "actual": actual_hash
                    })
                else:
                    verified_count += 1
            except Exception as e:
                failed_assets.append(rel_path)
                anomalies.append({"asset": rel_path, "error": str(e)})

        # Step 3: Check Thresholds
        try:
            self.verify_runtime_thresholds()
        except ThresholdTamperingError as te:
            failed_assets.append("runtime_thresholds")
            anomalies.append({
                "type": IntelligenceAnomalyType.THRESHOLD_MISMATCH.value,
                "error": str(te)
            })

        # Step 4: Check Rules
        try:
            self.verify_rules()
        except RuleTamperingError as re:
            failed_assets.append("detection_rules")
            anomalies.append({
                "type": IntelligenceAnomalyType.UNAUTHORIZED_RULE_CHANGE.value,
                "error": str(re)
            })

        is_valid = len(failed_assets) == 0
        if not is_valid:
            self.activate_safe_mode(
                f"Integrity sweep failed for {len(failed_assets)} intelligence assets.",
                IntelligenceAnomalyType.HASH_MISMATCH
            )

        self.last_verdict = IntelligenceIntegrityVerdict(
            is_valid=is_valid,
            safe_mode_active=self.safe_mode_active,
            verified_assets_count=verified_count,
            failed_assets=failed_assets,
            anomalies=anomalies,
            error_message=f"Failed assets: {', '.join(failed_assets)}" if failed_assets else None,
            checked_at=checked_at,
            checked_at_iso=checked_at_iso,
        )
        return self.last_verdict


# Global Singleton Instance
intelligence_guard = IntelligenceIntegrityGuard()
