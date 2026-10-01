"""
NetAudit  |  core/scanner.py
Multi-threaded TCP port scanner with service banner grabbing.
"""

import socket
import concurrent.futures
import time
from dataclasses import dataclass, field
from typing import Optional


# ── Result container ──────────────────────────────────────────────────────────

@dataclass
class PortResult:
    port:    int
    state:   str          # "open" | "closed" | "filtered"
    banner:  Optional[str] = None
    latency: float        = 0.0   # ms


# ── Banner probe payloads ─────────────────────────────────────────────────────

BANNER_PROBES = {
    21:   b"",
    22:   b"",
    23:   b"",
    25:   b"EHLO netaudit\r\n",
    80:   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    443:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    110:  b"",
    143:  b"",
    3306: b"",
    5432: b"",
    6379: b"PING\r\n",
}

BANNER_TIMEOUT = 2.0   # seconds to wait for banner


def _grab_banner(sock: socket.socket, port: int) -> Optional[str]:
    """Send a probe and read back the banner (best-effort)."""
    try:
        probe = BANNER_PROBES.get(port, b"")
        if probe:
            sock.sendall(probe)
        raw = sock.recv(1024)
        banner = raw.decode("utf-8", errors="replace").strip()
        # Keep only first line and cap length
        banner = banner.split("\n")[0][:120]
        return banner if banner else None
    except Exception:
        return None


# ── Per-port scan ─────────────────────────────────────────────────────────────

def scan_port(host: str, port: int, timeout: float = 1.0) -> PortResult:
    """
    Try to TCP-connect to host:port.
    Returns a PortResult with state, optional banner, and latency.
    """
    start = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((host, port))
            latency = (time.perf_counter() - start) * 1000   # → ms
            if code == 0:
                sock.settimeout(BANNER_TIMEOUT)
                banner = _grab_banner(sock, port)
                return PortResult(port=port, state="open", banner=banner, latency=round(latency, 1))
            else:
                return PortResult(port=port, state="closed", latency=round(latency, 1))
    except socket.timeout:
        return PortResult(port=port, state="filtered", latency=round((time.perf_counter() - start) * 1000, 1))
    except OSError:
        return PortResult(port=port, state="filtered", latency=0.0)


# ── Threaded scanner ──────────────────────────────────────────────────────────

def run_scan(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    max_workers: int = 150,
    progress_callback=None
) -> list[PortResult]:
    """
    Scan a list of ports concurrently using a thread pool.
    Calls progress_callback(done, total) after each port completes.
    Returns only open ports, sorted ascending.
    """
    results = []
    done = 0
    total = len(ports)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(scan_port, host, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            done += 1
            if result.state == "open":
                results.append(result)
            if progress_callback:
                progress_callback(done, total)

    return sorted(results, key=lambda r: r.port)


# ── Port list presets ─────────────────────────────────────────────────────────

# The 50 most security-relevant ports
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 137, 139,
    143, 443, 445, 512, 513, 514, 587, 631, 993, 995,
    1433, 1521, 2049, 2181, 3306, 3389, 4444, 5432,
    5900, 5984, 6379, 6443, 7001, 8080, 8443, 8888,
    9000, 9200, 9300, 27017, 27018, 28017,
]

# Extended 1–1024 sweep
FULL_PORTS = list(range(1, 1025)) + [
    1433, 1521, 2049, 3306, 3389, 4444, 5432,
    5900, 6379, 8080, 8443, 9200, 27017,
]
