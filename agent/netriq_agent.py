import os
import sys
import time
import socket
import json
import uuid
import platform
import subprocess
import urllib.request
import urllib.error
from typing import List, Dict, Any, Tuple

# Configuration
_cli_server = None
if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
    _cli_server = sys.argv[1].strip()
    if not _cli_server.startswith("http://") and not _cli_server.startswith("https://"):
        _cli_server = f"http://{_cli_server}"

SERVER_URL = (_cli_server or os.environ.get("NETRIQ_SERVER_URL", "http://127.0.0.1:8000")).rstrip("/")
REPORT_INTERVAL = int(os.environ.get("NETRIQ_INTERVAL", "15"))  # seconds between heartbeats

SUSPICIOUS_SIGNATURES = {
    "mimikatz.exe", "nmap.exe", "wireshark.exe", "hping3", "hydra.exe",
    "nc.exe", "netcat", "cain.exe", "john.exe", "metasploit", "responder.py",
    "sqlmap", "cobaltstrike", "psexec.exe", "chisel.exe"
}

def get_mac_address() -> str:
    """Retrieves hardware MAC address formatted as XX:XX:XX:XX:XX:XX."""
    try:
        raw_mac = uuid.getnode()
        return ':'.join(f"{(raw_mac >> ele) & 0xff:02X}" for ele in range(40, -8, -8))
    except Exception:
        return "00:00:00:00:00:00"

def get_local_ip() -> str:
    """Retrieves the local LAN IP address bound to the primary interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def get_logged_in_user() -> str:
    """Retrieves the active logged-in OS username."""
    try:
        return os.getlogin()
    except Exception:
        return os.environ.get("USERNAME", os.environ.get("USER", "Unknown"))

def is_elevated() -> bool:
    """Checks if the agent process is executing with administrative / root privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def get_authentication_events() -> List[Dict[str, Any]]:
    """Collects current OS session/login events."""
    events = []
    user = get_logged_in_user()
    now = time.time()
    
    events.append({
        "user": user,
        "status": "active_session",
        "is_elevated": is_elevated(),
        "time": now
    })
    return events

def get_process_metadata() -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Collects process execution metadata (PID, name, command line)
    and tags known suspicious tools.
    """
    processes: List[Dict[str, Any]] = []
    suspicious_found: List[str] = []

    if platform.system() == "Windows":
        try:
            # Query tasklist with CSV format for fast, non-blocking execution
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                text=True, stderr=subprocess.DEVNULL, timeout=4
            )
            for line in out.splitlines():
                if not line.strip():
                    continue
                parts = [p.replace('"', '').strip() for p in line.split('","')]
                if len(parts) >= 2:
                    p_name = parts[0].lower()
                    try:
                        p_pid = int(parts[1])
                    except ValueError:
                        p_pid = None

                    is_susp = p_name in SUSPICIOUS_SIGNATURES
                    if is_susp and p_name not in suspicious_found:
                        suspicious_found.append(p_name)

                    processes.append({
                        "name": p_name,
                        "pid": p_pid,
                        "is_suspicious": is_susp,
                        "timestamp": time.time()
                    })
        except Exception:
            pass
    else:
        try:
            out = subprocess.check_output(
                ["ps", "-eo", "pid,ppid,comm"],
                text=True, stderr=subprocess.DEVNULL, timeout=4
            )
            for line in out.splitlines()[1:]:
                parts = line.strip().split(None, 2)
                if len(parts) >= 3:
                    p_name = parts[2].lower()
                    is_susp = p_name in SUSPICIOUS_SIGNATURES
                    if is_susp and p_name not in suspicious_found:
                        suspicious_found.append(p_name)
                    processes.append({
                        "pid": int(parts[0]),
                        "ppid": int(parts[1]),
                        "name": p_name,
                        "is_suspicious": is_susp,
                        "timestamp": time.time()
                    })
        except Exception:
            pass

    return processes[:60], suspicious_found

def get_network_connections() -> List[Dict[str, Any]]:
    """
    Collects active TCP/UDP network connection states (sockets)
    using native platform tools.
    """
    connections: List[Dict[str, Any]] = []
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(
                ["netstat", "-ano", "-p", "tcp"],
                text=True, stderr=subprocess.DEVNULL, timeout=4
            )
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("TCP"):
                    parts = line.split()
                    if len(parts) >= 5:
                        proto = parts[0]
                        local_addr = parts[1]
                        foreign_addr = parts[2]
                        state = parts[3]
                        try:
                            pid = int(parts[4])
                        except ValueError:
                            pid = None

                        l_ip, _, l_port = local_addr.rpartition(":")
                        r_ip, _, r_port = foreign_addr.rpartition(":")

                        # Filter out listening on localhost only
                        if r_ip and r_ip not in ("0.0.0.0", "*", "[::]"):
                            connections.append({
                                "protocol": proto,
                                "local_ip": l_ip,
                                "local_port": int(l_port) if l_port.isdigit() else 0,
                                "remote_ip": r_ip,
                                "remote_port": int(r_port) if r_port.isdigit() else 0,
                                "state": state,
                                "pid": pid,
                                "timestamp": time.time()
                            })
        else:
            out = subprocess.check_output(
                ["netstat", "-ant"],
                text=True, stderr=subprocess.DEVNULL, timeout=4
            )
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("tcp"):
                    parts = line.split()
                    if len(parts) >= 6:
                        l_addr = parts[3]
                        r_addr = parts[4]
                        state = parts[5]
                        l_ip, _, l_port = l_addr.rpartition(":")
                        r_ip, _, r_port = r_addr.rpartition(":")
                        if r_ip and r_ip not in ("0.0.0.0", "*", ":::*"):
                            connections.append({
                                "protocol": "TCP",
                                "local_ip": l_ip,
                                "local_port": int(l_port) if l_port.isdigit() else 0,
                                "remote_ip": r_ip,
                                "remote_port": int(r_port) if r_port.isdigit() else 0,
                                "state": state,
                                "timestamp": time.time()
                            })
    except Exception:
        pass

    return connections[:30]

def collect_full_telemetry() -> Dict[str, Any]:
    """Assembles comprehensive Layer 1 endpoint telemetry payload."""
    mac = get_mac_address()
    ip = get_local_ip()
    hostname = socket.gethostname()
    username = get_logged_in_user()
    elevated = is_elevated()
    
    procs, suspicious_procs = get_process_metadata()
    conns = get_network_connections()
    auths = get_authentication_events()

    sample_proc_names = [p["name"] for p in procs[:15]]

    return {
        "mac": mac,
        "ip": ip,
        "hostname": hostname,
        "os": f"{platform.system()} {platform.release()}",
        "logged_in_user": username,
        "is_elevated": elevated,
        "active_processes_count": len(procs),
        "sample_processes": sample_proc_names,
        "processes": procs,
        "connections": conns,
        "auth_events": auths,
        "suspicious_processes": suspicious_procs,
        "timestamp": time.time()
    }

def send_telemetry(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Sends telemetry payload to the NetrIQ central API."""
    endpoint = f"{SERVER_URL}/api/v1/telemetry/endpoint"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "NetrIQ-EndpointSensor/2.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # Fallback to legacy endpoint if new endpoint not yet reachable
        if e.code == 404:
            return send_legacy_heartbeat(payload)
        return {"status": "error", "message": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def send_legacy_heartbeat(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Backwards compatibility fallback."""
    legacy_endpoint = f"{SERVER_URL}/api/v1/behaviors/agent-heartbeat"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        legacy_endpoint,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "NetrIQ-EndpointSensor/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"status": "error", "message": str(e)}

def main():
    print("=" * 70)
    print("   NETRIQ LAYER 1 ENDPOINT TELEMETRY AGENT")
    print("   Data Acquisition: Logins | Processes | Sockets | OS Events")
    print("=" * 70)
    print(f"[*] Target NetrIQ Server : {SERVER_URL}")
    print(f"[*] Telemetry Interval   : {REPORT_INTERVAL}s")
    print(f"[*] Host Identity        : {socket.gethostname()} ({get_local_ip()})")
    print(f"[*] Hardware MAC Address : {get_mac_address()}")
    print(f"[*] Logged-in User       : {get_logged_in_user()} (Elevated: {is_elevated()})")
    print("-" * 70)

    while True:
        try:
            telemetry = collect_full_telemetry()
            res = send_telemetry(telemetry)

            if res.get("status") == "success":
                quarantined = res.get("is_quarantined", False)
                if quarantined:
                    print(f"\n[!] ALERT: Endpoint has been QUARANTINED by SOC Admin policy.")
                else:
                    conns_count = len(telemetry.get("connections", []))
                    procs_count = telemetry.get("active_processes_count", 0)
                    susp_info = f" | [!] SUSPICIOUS TOOLS: {telemetry['suspicious_processes']}" if telemetry["suspicious_processes"] else ""
                    print(f"[{time.strftime('%H:%M:%S')}] Telemetry Streamed -> {SERVER_URL} (Procs: {procs_count}, Active Sockets: {conns_count}{susp_info})")
            else:
                print(f"[{time.strftime('%H:%M:%S')}] NetrIQ Server unreachable ({res.get('message', 'offline')}). Retrying...")

        except KeyboardInterrupt:
            print("\n[*] NetrIQ Telemetry Agent stopped by user.")
            sys.exit(0)
        except Exception as e:
            print(f"[*] Agent telemetry error: {e}")

        time.sleep(REPORT_INTERVAL)

if __name__ == "__main__":
    main()
