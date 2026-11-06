"""
NetrIQ Sensor Security & Confinement Package
Implements privilege dropping, resource bounding, seccomp profiling, and engine hardening
to protect sensors against maliciously crafted network traffic and parser exploits.
"""
from sensor.security.confinement import (
    drop_privileges,
    apply_resource_limits,
    generate_seccomp_profile,
    validate_environment_security
)

__all__ = [
    "drop_privileges",
    "apply_resource_limits",
    "generate_seccomp_profile",
    "validate_environment_security"
]

