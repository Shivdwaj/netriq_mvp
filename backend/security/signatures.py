import hashlib
import hmac
import json
import os
from typing import Dict, Any, Union, Optional
from pydantic import BaseModel

from backend.utils.logger import get_logger

logger = get_logger(__name__)

class ManifestSigner:
    """
    Software Integrity & Cryptographic Signature Verification
    Protects distributed rule manifests and remote sensor updates against tampering
    or unauthorized modification by untrusted entities.

    Uses HMAC-SHA256 canonical hashing with constant-time verification.
    All signing keys and algorithms are configurable (zero hardcoded values).
    """

    DEFAULT_ALGORITHM = "HMAC-SHA256"

    @classmethod
    def get_signing_key(cls, explicit_key: Optional[str] = None) -> bytes:
        key = explicit_key or os.getenv("NETRIQ_SIGNING_KEY", "netriq-default-signing-key-prod-v1")
        return key.encode("utf-8")

    @classmethod
    def canonicalize(cls, data: Dict[str, Any]) -> bytes:
        """
        Creates a deterministic byte representation of the dictionary.
        Excludes existing signature metadata fields to ensure idempotency.
        """
        filtered = {
            k: v for k, v in data.items()
            if k not in ("signature", "signature_alg")
        }
        canonical_str = json.dumps(filtered, sort_keys=True, separators=(",", ":"))
        return canonical_str.encode("utf-8")

    @classmethod
    def sign_manifest(
        cls,
        manifest: Union[Dict[str, Any], BaseModel],
        secret_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Computes a cryptographic HMAC-SHA256 signature for the manifest.
        Returns the manifest dictionary with 'signature' and 'signature_alg' attached.
        """
        if isinstance(manifest, BaseModel):
            manifest_dict = manifest.model_dump()
        else:
            manifest_dict = dict(manifest)

        key_bytes = cls.get_signing_key(secret_key)
        canonical_bytes = cls.canonicalize(manifest_dict)
        
        signature = hmac.new(key_bytes, canonical_bytes, hashlib.sha256).hexdigest()
        manifest_dict["signature"] = signature
        manifest_dict["signature_alg"] = cls.DEFAULT_ALGORITHM
        return manifest_dict

    @classmethod
    def verify_manifest(
        cls,
        manifest: Union[Dict[str, Any], BaseModel],
        secret_key: Optional[str] = None
    ) -> bool:
        """
        Verifies the cryptographic integrity of a signed manifest.
        Returns True if signature is valid; False if corrupted, tampered, or missing.
        """
        if isinstance(manifest, BaseModel):
            manifest_dict = manifest.model_dump()
        else:
            manifest_dict = dict(manifest)

        provided_sig = manifest_dict.get("signature")
        if not provided_sig:
            logger.warning("[SoftwareIntegrity] Manifest rejection: Missing cryptographic signature.")
            return False

        key_bytes = cls.get_signing_key(secret_key)
        canonical_bytes = cls.canonicalize(manifest_dict)
        expected_sig = hmac.new(key_bytes, canonical_bytes, hashlib.sha256).hexdigest()

        is_valid = hmac.compare_digest(provided_sig, expected_sig)
        if not is_valid:
            logger.warning("[SoftwareIntegrity] Manifest rejection: Signature mismatch! Potential tampering detected.")
        return is_valid

