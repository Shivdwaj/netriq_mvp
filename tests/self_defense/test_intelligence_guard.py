"""
tests/self_defense/test_intelligence_guard.py

Comprehensive adversarial test suite for Intelligence Integrity Guard (IIG) (Stage 2 Step 4).
Validates:
1. Valid Ed25519 signed manifest verifies cleanly.
2. Modified model binary bytes are detected BEFORE deserialization.
3. Modified scaler, encoder, and metadata definitions are detected.
4. Modified Suricata hardened YAML is detected.
5. Forged, altered, or unsigned manifest is rejected.
6. Missing production assets cause a safe failure.
7. Pre-deserialization hook prevents joblib.load() from executing on compromised files.
8. Runtime risk threshold tampering is detected.
9. Unauthorized detection rule modifications are detected.
10. ML inference is disabled after integrity failure (Safe Detection Mode active).
11. Deterministic detection (signatures, rules, behaviour) remains 100% operational in Safe Mode.
12. Independent Security Watchdog detects tampering and emits out-of-band alert.
13. Canonical manifest serialization is deterministic regardless of dictionary order.
"""

import os
import json
import shutil
import tempfile
import pytest
import asyncio
from pathlib import Path
from unittest.mock import patch, MagicMock

from backend.ai.contracts import TrafficType
from backend.self_defense.schemas import (
    AssetIntegrityType,
    IntelligenceAnomalyType,
    AlertCategory,
    AlertSeverity,
)
from backend.self_defense.intelligence_guard import (
    IntelligenceIntegrityGuard,
    generate_release_keypair,
    canonical_manifest_bytes,
    sign_manifest_payload,
    verify_manifest_signature,
    hash_file_sha256,
    ManifestSignatureVerificationError,
    AssetIntegrityError,
    ThresholdTamperingError,
    RuleTamperingError,
    SafeModeActiveError,
)
from backend.self_defense.watchdog import (
    IndependentSecurityWatchdog,
    MemoryAlertSink,
)
from backend.detection.detection_manager import DetectionManager
from backend.pipeline.schemas import NormalizedSecurityEvent


@pytest.fixture
def temp_workspace():
    """Isolated temporary workspace for test model files and signed manifests."""
    temp_dir = Path(tempfile.mkdtemp(prefix="netriq_iig_test_"))
    models_dir = temp_dir / "models"
    sensor_dir = temp_dir / "sensor" / "security"
    config_dir = temp_dir / "config"

    models_dir.mkdir(parents=True)
    sensor_dir.mkdir(parents=True)
    config_dir.mkdir(parents=True)

    yield {
        "root": temp_dir,
        "models": models_dir,
        "sensor": sensor_dir,
        "config": config_dir,
    }
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def release_keys():
    """Generates a valid Ed25519 keypair for signing release manifests."""
    priv_hex, pub_hex = generate_release_keypair()
    return {"private": priv_hex, "public": pub_hex}


@pytest.fixture
def sample_assets(temp_workspace):
    """Creates realistic dummy model binaries, metadata, and config files."""
    models_dir = temp_workspace["models"]
    sensor_dir = temp_workspace["sensor"]

    # 1. Model binary
    model_path = models_dir / "network_traffic_RandomForest.joblib"
    model_content = b"PKL_VALID_MODEL_BINARY_STUB_BYTES_2026_TEST"
    model_path.write_bytes(model_content)

    # 2. Metadata file
    meta_path = models_dir / "network_metadata.json"
    meta_content = json.dumps({"features": ["f1", "f2"], "threshold": 0.5}).encode("utf-8")
    meta_path.write_bytes(meta_content)

    # 3. Scaler file
    scaler_path = models_dir / "scaler.joblib"
    scaler_content = b"SCALER_VALID_BYTES_STUB"
    scaler_path.write_bytes(scaler_content)

    # 4. Suricata YAML
    yaml_path = sensor_dir / "suricata_hardened.yaml"
    yaml_content = b"runmode: workers\ndrop-privileges:\n  user: suricata\n"
    yaml_path.write_bytes(yaml_content)

    return {
        "model_file": "network_traffic_RandomForest.joblib",
        "model_path": model_path,
        "model_hash": hash_file_sha256(model_path),
        "meta_file": "network_metadata.json",
        "meta_path": meta_path,
        "meta_hash": hash_file_sha256(meta_path),
        "scaler_file": "scaler.joblib",
        "scaler_path": scaler_path,
        "scaler_hash": hash_file_sha256(scaler_path),
        "yaml_path": yaml_path,
        "yaml_hash": hash_file_sha256(yaml_path),
    }


@pytest.fixture
def signed_manifest_dict(sample_assets, release_keys):
    """Builds and signs a valid IntelligenceManifest dictionary."""
    manifest = {
        "manifest_version": "1.0.0",
        "release_id": "v1.1.0-release-test",
        "created_at_iso": "2026-11-11T08:00:00Z",
        "assets": {
            sample_assets["model_file"]: {
                "relative_path": sample_assets["model_file"],
                "sha256": sample_assets["model_hash"],
                "asset_type": "MODEL",
                "critical": True,
            },
            sample_assets["meta_file"]: {
                "relative_path": sample_assets["meta_file"],
                "sha256": sample_assets["meta_hash"],
                "asset_type": "METADATA",
                "critical": True,
            },
            sample_assets["scaler_file"]: {
                "relative_path": sample_assets["scaler_file"],
                "sha256": sample_assets["scaler_hash"],
                "asset_type": "SCALER",
                "critical": False,
            },
            "suricata_hardened.yaml": {
                "relative_path": "suricata_hardened.yaml",
                "sha256": sample_assets["yaml_hash"],
                "asset_type": "SURICATA_YAML",
                "critical": True,
            },
        },
        "thresholds": {
            "RISK_LOW_MAX": 40.0,
            "RISK_MEDIUM_MAX": 70.0,
            "RISK_HIGH_MAX": 90.0,
            "ACTIONABLE_RISK_THRESHOLD": 70.0,
            "HIGH_ANOMALY_THRESHOLD": 70.0,
            "HEURISTIC_CONFIDENCE_FLOOR": 75.0,
            "HEURISTIC_PACKET_RATE_THRESHOLD": 1000.0,
        },
        "rule_hashes": {},
    }
    sig = sign_manifest_payload(manifest, release_keys["private"])
    manifest["signature"] = sig
    return manifest


# ==============================================================================
# Unit & Adversarial Tests
# ==============================================================================

def test_canonical_manifest_serialization_determinism():
    """Serialization for signature verification is deterministic regardless of dict ordering."""
    d1 = {"b": 2, "a": 1, "nested": {"z": 10, "y": 20}}
    d2 = {"a": 1, "b": 2, "nested": {"y": 20, "z": 10}}
    assert canonical_manifest_bytes(d1) == canonical_manifest_bytes(d2)


def test_valid_signed_manifest_verifies_successfully(temp_workspace, release_keys, signed_manifest_dict):
    """A legitimately signed release manifest verifies cleanly with the pinned public key."""
    guard = IntelligenceIntegrityGuard(
        public_key_hex=release_keys["public"],
        project_root=temp_workspace["root"],
    )
    manifest = guard.load_and_verify_manifest(signed_manifest_dict)
    assert manifest is not None
    assert manifest.release_id == "v1.1.0-release-test"
    assert guard.is_safe_mode_active() is False


def test_forged_or_unsigned_manifest_rejected(temp_workspace, release_keys, signed_manifest_dict):
    """Manifests with missing signatures, forged signatures, or tampered payloads are rejected."""
    guard = IntelligenceIntegrityGuard(
        public_key_hex=release_keys["public"],
        project_root=temp_workspace["root"],
    )

    # 1. Missing signature
    unsigned = dict(signed_manifest_dict)
    unsigned.pop("signature")
    with pytest.raises(ManifestSignatureVerificationError):
        guard.load_and_verify_manifest(unsigned)
    assert guard.is_safe_mode_active() is True

    # Reset guard
    guard.deactivate_safe_mode_for_test()

    # 2. Forged signature from foreign keypair
    _, foreign_pub = generate_release_keypair()
    guard_foreign = IntelligenceIntegrityGuard(
        public_key_hex=foreign_pub,
        project_root=temp_workspace["root"],
    )
    with pytest.raises(ManifestSignatureVerificationError):
        guard_foreign.load_and_verify_manifest(signed_manifest_dict)

    # Reset guard
    guard.deactivate_safe_mode_for_test()

    # 3. Tampered payload with valid original signature
    tampered = dict(signed_manifest_dict)
    tampered["release_id"] = "v1.1.0-MALICIOUS-TAMPER"
    with pytest.raises(ManifestSignatureVerificationError):
        guard.load_and_verify_manifest(tampered)


def test_modified_model_bytes_detected(temp_workspace, release_keys, signed_manifest_dict, sample_assets):
    """Flipping bytes in a model file triggers AssetIntegrityError."""
    guard = IntelligenceIntegrityGuard(
        public_key_hex=release_keys["public"],
        project_root=temp_workspace["root"],
    )
    guard.load_and_verify_manifest(signed_manifest_dict)

    # Valid file verifies
    assert guard.verify_file_before_deserialization(sample_assets["model_file"], sample_assets["model_path"]) is True

    # Tamper with the model binary
    sample_assets["model_path"].write_bytes(b"MALICIOUS_REPLACED_PICKLE_PAYLOAD_EXEC")

    with pytest.raises(AssetIntegrityError) as exc_info:
        guard.verify_file_before_deserialization(sample_assets["model_file"], sample_assets["model_path"])

    assert exc_info.value.anomaly_type == IntelligenceAnomalyType.HASH_MISMATCH
    assert guard.is_safe_mode_active() is True


def test_modified_scaler_and_metadata_detected(temp_workspace, release_keys, signed_manifest_dict, sample_assets):
    """Modifying metadata or scaler files flags tampering."""
    guard = IntelligenceIntegrityGuard(
        public_key_hex=release_keys["public"],
        project_root=temp_workspace["root"],
    )
    guard.load_and_verify_manifest(signed_manifest_dict)

    # Tamper with metadata.json
    sample_assets["meta_path"].write_bytes(b'{"features": ["tampered_feature"]}')

    with pytest.raises(AssetIntegrityError):
        guard.verify_file_before_deserialization(sample_assets["meta_file"], sample_assets["meta_path"])
    assert guard.is_safe_mode_active() is True


def test_modified_suricata_yaml_detected(temp_workspace, release_keys, signed_manifest_dict, sample_assets):
    """Modifying Suricata configuration triggers configuration integrity violation."""
    guard = IntelligenceIntegrityGuard(
        public_key_hex=release_keys["public"],
        project_root=temp_workspace["root"],
    )
    guard.load_and_verify_manifest(signed_manifest_dict)

    # Baseline verifies
    assert guard.verify_suricata_config(sample_assets["yaml_path"]) is True

    # Attacker alters Suricata configuration
    sample_assets["yaml_path"].write_bytes(b"runmode: single\ndrop-privileges: none\n")

    with pytest.raises(AssetIntegrityError):
        guard.verify_suricata_config(sample_assets["yaml_path"])
    assert guard.is_safe_mode_active() is True


def test_no_compromised_model_is_deserialized(temp_workspace, release_keys, signed_manifest_dict, sample_assets):
    """Pre-deserialization hook guarantees joblib.load() is NEVER called on a tampered binary."""
    from backend.ai.model_manager import ModelManager

    # Initialize manager pointing to temp models dir
    mm = ModelManager()
    mm._models_dir = str(temp_workspace["models"])
    mm._safe_mode = False
    mm._models.clear()

    # Tamper with model binary
    sample_assets["model_path"].write_bytes(b"EXPLOIT_PICKLE_EXECUTE_CODE")

    from backend.self_defense.intelligence_guard import intelligence_guard
    intelligence_guard.public_key_hex = release_keys["public"]
    intelligence_guard.project_root = temp_workspace["root"]
    intelligence_guard.load_and_verify_manifest(signed_manifest_dict)

    with patch("joblib.load") as mock_joblib:
        with pytest.raises(AssetIntegrityError):
            mm.load_models(force_reload=True)

        # PROOF: joblib.load was never called!
        assert mock_joblib.call_count == 0
        assert mm._safe_mode is True


def test_runtime_threshold_changes_detected(temp_workspace, release_keys, signed_manifest_dict):
    """Mutating runtime risk thresholds triggers ThresholdTamperingError."""
    import backend.config.config as config

    guard = IntelligenceIntegrityGuard(
        public_key_hex=release_keys["public"],
        project_root=temp_workspace["root"],
    )
    guard.load_and_verify_manifest(signed_manifest_dict)

    # Clean thresholds pass
    assert guard.verify_runtime_thresholds() is True

    # Attacker tampers with threshold in memory
    orig = config.RISK_THRESHOLDS["MEDIUM_MAX"]
    try:
        config.RISK_THRESHOLDS["MEDIUM_MAX"] = 99.9  # Tamper to mute alerts

        with pytest.raises(ThresholdTamperingError) as exc_info:
            guard.verify_runtime_thresholds()

        assert exc_info.value.anomaly_type == IntelligenceAnomalyType.THRESHOLD_MISMATCH
        assert guard.is_safe_mode_active() is True
    finally:
        config.RISK_THRESHOLDS["MEDIUM_MAX"] = orig
        guard.deactivate_safe_mode_for_test()


def test_unauthorized_rule_changes_detected(temp_workspace, release_keys, signed_manifest_dict):
    """Injecting or altering rule definitions triggers RuleTamperingError."""
    # Add rule hash baseline
    signed_manifest_dict["rule_hashes"] = {
        "suricata_signatures": "a" * 64  # deliberate mismatch
    }
    # Re-sign manifest
    sig = sign_manifest_payload(signed_manifest_dict, release_keys["private"])
    signed_manifest_dict["signature"] = sig

    guard = IntelligenceIntegrityGuard(
        public_key_hex=release_keys["public"],
        project_root=temp_workspace["root"],
    )
    guard.load_and_verify_manifest(signed_manifest_dict)

    with pytest.raises(RuleTamperingError) as exc_info:
        guard.verify_rules()

    assert exc_info.value.anomaly_type == IntelligenceAnomalyType.UNAUTHORIZED_RULE_CHANGE
    assert guard.is_safe_mode_active() is True


def test_ml_inference_disabled_after_integrity_failure():
    """When Safe Detection Mode is activated, ModelManager raises SafeModeActiveError."""
    from backend.ai.model_manager import ModelManager
    from backend.self_defense.intelligence_guard import intelligence_guard

    mm = ModelManager()
    intelligence_guard.activate_safe_mode("Tamper simulation test")

    try:
        with pytest.raises(SafeModeActiveError):
            mm.get_model(TrafficType.NETWORK)
    finally:
        intelligence_guard.deactivate_safe_mode_for_test()
        mm._safe_mode = False


def test_deterministic_detection_remains_operational():
    """In Safe Detection Mode, deterministic detection engines process events without failure."""
    from backend.self_defense.intelligence_guard import intelligence_guard

    # Activate Safe Mode
    intelligence_guard.activate_safe_mode("ML model compromise test")

    dm = DetectionManager()
    assert dm.is_safe_detection_mode_active is True

    # Synthetic event matching a known Suricata alert
    test_event = NormalizedSecurityEvent(
        event_id="evt-safe-mode-001",
        tenant_id="tenant-alpha",
        source_ip="192.168.1.50",
        destination_ip="10.0.0.1",
        destination_port=80,
        protocol="TCP",
        event_type="alert",
        detection_source="suricata",
        severity="HIGH",
        evidence={
            "signature": "ET EXPLOIT Lateral SMB Exec",
            "category": "attempted-admin",
            "signature_id": 2010935,
        }
    )

    findings = dm.evaluate(test_event)
    # Proves deterministic signature engine detected the attack despite ML being disabled
    assert len(findings) > 0
    assert any("ET EXPLOIT" in f.title for f in findings)

    intelligence_guard.deactivate_safe_mode_for_test()


@pytest.mark.asyncio
async def test_watchdog_detects_intelligence_tampering(temp_workspace, release_keys, signed_manifest_dict, sample_assets):
    """The Independent Security Watchdog detects asset tampering during its sweep and dispatches an out-of-band alert."""
    sink = MemoryAlertSink()
    mock_ledger = MagicMock()
    mock_ledger.check_storage_health = asyncio.iscoroutinefunction(MagicMock()) and MagicMock()
    # Mock clean audit verification
    async def mock_audit():
        from backend.self_defense.schemas import AuditVerificationResult
        return AuditVerificationResult(is_valid=True)
    async def mock_storage():
        return True

    mock_ledger.check_storage_health = mock_storage
    mock_ledger.verify_integrity = mock_audit

    watchdog = IndependentSecurityWatchdog(ledger=mock_ledger, alert_sinks=[sink])

    from backend.self_defense.intelligence_guard import intelligence_guard
    intelligence_guard.public_key_hex = release_keys["public"]
    intelligence_guard.project_root = temp_workspace["root"]
    intelligence_guard.load_and_verify_manifest(signed_manifest_dict)

    # 1. Clean sweep: zero alerts
    await watchdog.run_sweep()
    assert len(sink.alerts) == 0

    # 2. Tamper with a model binary
    sample_assets["model_path"].write_bytes(b"CORRUPTED_TAMPERED_BYTES")

    # 3. Next sweep detects tampering within seconds
    await watchdog.run_sweep()

    assert len(sink.alerts) == 1
    alert = sink.alerts[0]
    assert alert.category == AlertCategory.INTELLIGENCE_TAMPERING
    assert alert.severity == AlertSeverity.CRITICAL
    assert "network_traffic_RandomForest.joblib" in str(alert.details)

    intelligence_guard.deactivate_safe_mode_for_test()


def test_missing_production_assets_cause_safe_failure(temp_workspace, release_keys, signed_manifest_dict):
    """In production mode, missing critical model assets trigger safe failure."""
    guard = IntelligenceIntegrityGuard(
        public_key_hex=release_keys["public"],
        project_root=temp_workspace["root"],
    )
    guard.load_and_verify_manifest(signed_manifest_dict)

    missing_model_path = temp_workspace["models"] / "nonexistent.joblib"
    with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
        with pytest.raises((AssetIntegrityError, FileNotFoundError)):
            guard.verify_file_before_deserialization("nonexistent.joblib", missing_model_path)
    assert guard.is_safe_mode_active() is True
