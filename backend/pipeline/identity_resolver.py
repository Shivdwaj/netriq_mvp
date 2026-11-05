import time
from typing import Optional, Dict
from backend.utils.logger import get_logger
from backend.pipeline.schemas import DeviceIdentity

logger = get_logger(__name__)

class IdentityResolver:
    """
    Maintains a mapping of IP <-> MAC <-> Hostname <-> User.
    Enriches raw network packets and endpoint events with authoritative device identities.
    """

    def __init__(self, cache_ttl_seconds: float = 300.0):
        self._ip_to_identity: Dict[str, Dict] = {}
        self._mac_to_identity: Dict[str, Dict] = {}
        self._cache_ttl = cache_ttl_seconds

    def register_device(
        self,
        ip: str,
        mac: Optional[str] = None,
        hostname: Optional[str] = None,
        os_name: Optional[str] = None,
        logged_in_user: Optional[str] = None,
        is_managed: bool = True
    ) -> DeviceIdentity:
        """Registers or updates a device identity in the resolver cache."""
        now = time.time()
        record = {
            "ip": ip,
            "mac": mac.upper() if mac else None,
            "hostname": hostname or "unknown",
            "os_name": os_name,
            "logged_in_user": logged_in_user,
            "is_managed": is_managed,
            "updated_at": now
        }
        if ip:
            self._ip_to_identity[ip] = record
        if mac:
            self._mac_to_identity[mac.upper()] = record

        return DeviceIdentity(
            hostname=record["hostname"],
            mac=record["mac"],
            ip=record["ip"],
            os_name=record["os_name"],
            logged_in_user=record["logged_in_user"],
            is_managed=record["is_managed"]
        )

    def resolve(self, ip: Optional[str] = None, mac: Optional[str] = None) -> DeviceIdentity:
        """
        Attempts to resolve DeviceIdentity from IP or MAC address.
        Falls back to a default unmanaged identity if not registered.
        """
        now = time.time()
        if mac and mac.upper() in self._mac_to_identity:
            rec = self._mac_to_identity[mac.upper()]
            if now - rec.get("updated_at", 0) <= self._cache_ttl:
                return DeviceIdentity(**{k: v for k, v in rec.items() if k != "updated_at"})

        if ip and ip in self._ip_to_identity:
            rec = self._ip_to_identity[ip]
            if now - rec.get("updated_at", 0) <= self._cache_ttl:
                return DeviceIdentity(**{k: v for k, v in rec.items() if k != "updated_at"})

        # Unknown / unmanaged endpoint
        return DeviceIdentity(
            hostname="unmanaged-endpoint",
            mac=mac.upper() if mac else None,
            ip=ip,
            os_name=None,
            logged_in_user=None,
            is_managed=False
        )

identity_resolver = IdentityResolver()

