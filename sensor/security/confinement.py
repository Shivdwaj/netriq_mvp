import os
import sys
import json
from typing import Dict, Any, Optional
from backend.utils.logger import get_logger

logger = get_logger(__name__)

def drop_privileges(user: str = "zeek", group: str = "zeek") -> bool:
    """
    Drops root privileges on POSIX sensor hosts after binding to raw capture sockets.
    Mitigates privilege escalation risks from parser vulnerabilities in Suricata or Zeek.
    Gracefully no-ops on Windows or non-POSIX platforms.
    """
    if os.name != "posix":
        logger.info(f"[SecurityConfinement] Non-POSIX OS detected ({sys.platform}). Privilege dropping is bypassed in dev/testing.")
        return True

    try:
        import pwd
        import grp

        # If already unprivileged, do nothing
        if os.getuid() != 0:
            logger.info(f"[SecurityConfinement] Sensor daemon running as unprivileged UID {os.getuid()}. No privilege drop required.")
            return True

        target_uid = pwd.getpwnam(user).pw_uid
        target_gid = grp.getgrnam(group).gr_gid

        # Set secondary groups to target group
        os.setgroups([target_gid])
        # Change real and effective GID
        os.setgid(target_gid)
        # Change real and effective UID
        os.setuid(target_uid)

        # Ensure privileges cannot be regained
        if hasattr(os, "prctl"):
            import ctypes
            # PR_SET_NO_NEW_PRIVS = 38
            ctypes.CDLL(None).prctl(38, 1, 0, 0, 0)

        logger.info(f"[SecurityConfinement] Successfully dropped root privileges to user '{user}' (UID {target_uid}, GID {target_gid}).")
        return True
    except Exception as e:
        logger.warning(f"[SecurityConfinement] Unable to drop privileges to {user}:{group}: {e}")
        return False

def apply_resource_limits(max_memory_mb: int = 2048, max_cpu_seconds: int = 0) -> bool:
    """
    Applies OS-level virtual memory limits (RLIMIT_AS) on POSIX hosts.
    Prevents crafted packet memory exhaustion (DoS / bomb) from crashing the sensor node.
    """
    try:
        import resource
        if max_memory_mb > 0:
            bytes_limit = max_memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (bytes_limit, bytes_limit))
            logger.info(f"[SecurityConfinement] Configured RLIMIT_AS memory bound to {max_memory_mb} MB.")
        if max_cpu_seconds > 0:
            resource.setrlimit(resource.RLIMIT_CPU, (max_cpu_seconds, max_cpu_seconds))
            logger.info(f"[SecurityConfinement] Configured RLIMIT_CPU bound to {max_cpu_seconds} seconds.")
        return True
    except (ImportError, AttributeError):
        # Module resource not available on Windows
        return True
    except Exception as e:
        logger.warning(f"[SecurityConfinement] Could not apply resource limits: {e}")
        return False

def generate_seccomp_profile(output_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Generates a hardened Seccomp BPF security profile for NetrIQ sensor containers.
    Restricts dangerous syscalls while permitting packet capture, IPC, and event spooling.
    """
    profile = {
        "defaultAction": "SCMP_ACT_ERRNO",
        "architectures": [
            "SCMP_ARCH_X86_64",
            "SCMP_ARCH_AARCH64"
        ],
        "syscalls": [
            {
                "names": [
                    "accept", "accept4", "bind", "connect", "getsockname", "getpeername",
                    "getsockopt", "setsockopt", "socket", "socketpair", "recv", "recvfrom",
                    "recvmsg", "recvmmsg", "send", "sendto", "sendmsg", "sendmmsg",
                    "shutdown", "poll", "epoll_create", "epoll_create1", "epoll_ctl",
                    "epoll_wait", "epoll_pwait", "select", "pselect6", "read", "readv",
                    "write", "writev", "pread64", "pwrite64", "open", "openat", "close",
                    "stat", "fstat", "lstat", "newfstatat", "lseek", "access", "faccessat",
                    "mmap", "mprotect", "munmap", "brk", "futex", "nanosleep", "clock_gettime",
                    "clock_getres", "clock_nanosleep", "gettimeofday", "time", "exit",
                    "exit_group", "getpid", "getppid", "getuid", "geteuid", "getgid", "getegid",
                    "clone", "clone3", "fork", "vfork", "execve", "execveat", "wait4", "waitid",
                    "pipe", "pipe2", "fcntl", "ioctl", "getrandom", "sysinfo", "prctl"
                ],
                "action": "SCMP_ACT_ALLOW"
            },
            {
                "names": [
                    "ptrace", "process_vm_readv", "process_vm_writev",
                    "reboot", "kexec_load", "kexec_file_load",
                    "mount", "umount", "umount2", "pivot_root",
                    "swapon", "swapoff", "chroot", "init_module", "finit_module", "delete_module"
                ],
                "action": "SCMP_ACT_KILL"
            }
        ]
    }

    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(profile, f, indent=2)
            logger.info(f"[SecurityConfinement] Seccomp profile saved to {output_path}")
        except Exception as e:
            logger.error(f"[SecurityConfinement] Failed to save seccomp profile to {output_path}: {e}")

    return profile

def validate_environment_security() -> Dict[str, Any]:
    """
    Performs an operational security audit of the sensor host environment.
    Flags high-risk configurations like running root without isolation.
    """
    findings = []
    is_hardened = True

    is_posix = os.name == "posix"
    is_root = (os.getuid() == 0) if is_posix and hasattr(os, "getuid") else False

    if is_root:
        findings.append("Running as root (UID 0) without privilege drop. Potential risk if protocol parser is exploited.")
        is_hardened = False

    # Check writable spool directory permissions
    spool_path = os.getenv("NETRIQ_SENSOR_SPOOL_PATH")
    if spool_path and os.path.exists(spool_path) and is_posix:
        mode = oct(os.stat(spool_path).st_mode)[-3:]
        if mode.endswith("7") or mode.endswith("6"): # World-writable
            findings.append(f"Spool path '{spool_path}' has insecure world permissions ({mode}).")
            is_hardened = False

    return {
        "is_hardened": is_hardened,
        "is_root": is_root,
        "platform": sys.platform,
        "findings": findings
    }

