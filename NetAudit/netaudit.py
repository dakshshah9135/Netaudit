#!/usr/bin/env python3
"""
NetAudit v1.0  —  Network Security Scanner & Risk Auditor
Author : Daksh Shah
GitHub : https://github.com/daksh-shah9135/netaudit

Usage:
  python netaudit.py <target>                     # Quick scan (common ports)
  python netaudit.py <target> --full              # Full 1-1024 + known-risk sweep
  python netaudit.py <target> --ports 22,80,443   # Specific ports
  python netaudit.py <target> --output report.html # Custom output filename
  python netaudit.py <target> --timeout 2.0        # Adjust timeout per port

WARNING: Only scan systems you own or have explicit written permission to scan.
Unauthorized port scanning may be illegal in your jurisdiction.
"""

import argparse
import sys
import time
import os
import datetime

from core.scanner  import run_scan, COMMON_PORTS, FULL_PORTS
from core.analyzer import analyze
from core.reporter import generate_html
from core.utils    import (
    print_banner, print_section, print_finding,
    print_score, progress_bar, C
)


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netaudit",
        description="NetAudit — Network Security Scanner & Risk Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python netaudit.py scanme.nmap.org
  python netaudit.py 192.168.1.1 --full
  python netaudit.py 10.0.0.1 --ports 22,80,443,8080
  python netaudit.py scanme.nmap.org --timeout 2 --output my_report.html
        """
    )
    p.add_argument("target",
        help="Hostname or IP address to scan")
    p.add_argument("--full", action="store_true",
        help="Extended scan: ports 1-1024 + all known-risk ports (~1100 ports)")
    p.add_argument("--ports", type=str, default=None,
        help="Comma-separated list of specific ports, e.g. 22,80,443")
    p.add_argument("--timeout", type=float, default=1.0,
        help="TCP connection timeout per port in seconds (default: 1.0)")
    p.add_argument("--threads", type=int, default=150,
        help="Number of parallel threads (default: 150)")
    p.add_argument("--output", type=str, default=None,
        help="Output HTML report filename (default: auto-generated)")
    p.add_argument("--no-report", action="store_true",
        help="Skip HTML report generation, show terminal output only")
    return p


# ── Validation ────────────────────────────────────────────────────────────────

def validate_target(target: str) -> str:
    """Basic sanity check on the target string."""
    import socket
    target = target.strip()
    if not target:
        print(f"{C.RED}Error: target cannot be empty.{C.RESET}")
        sys.exit(1)
    try:
        resolved = socket.gethostbyname(target)
        return target
    except socket.gaierror:
        print(f"{C.RED}Error: Cannot resolve hostname '{target}'. Check the address and your DNS.{C.RESET}")
        sys.exit(1)


def parse_ports(ports_str: str) -> list[int]:
    """Parse a comma-separated port string into a sorted list of ints."""
    try:
        ports = []
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        valid = sorted(set(p for p in ports if 1 <= p <= 65535))
        if not valid:
            raise ValueError
        return valid
    except ValueError:
        print(f"{C.RED}Error: Invalid port specification '{ports_str}'.{C.RESET}")
        sys.exit(1)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    print_banner()

    # ── Resolve target ────────────────────────────────────────────────────────
    target = validate_target(args.target)

    # ── Build port list ───────────────────────────────────────────────────────
    if args.ports:
        ports = parse_ports(args.ports)
        mode  = f"Custom ({len(ports)} ports)"
    elif args.full:
        ports = FULL_PORTS
        mode  = f"Full sweep ({len(ports)} ports)"
    else:
        ports = COMMON_PORTS
        mode  = f"Quick scan ({len(ports)} common security-relevant ports)"

    # ── Pre-scan info ─────────────────────────────────────────────────────────
    print_section("Scan Configuration")
    print(f"  Target     : {C.CYAN}{C.BOLD}{target}{C.RESET}")
    print(f"  Mode       : {mode}")
    print(f"  Timeout    : {args.timeout}s per port")
    print(f"  Threads    : {args.threads} parallel")

    print_section("Scanning…")

    # ── Run scan ──────────────────────────────────────────────────────────────
    start = time.perf_counter()

    def on_progress(done, total):
        progress_bar(done, total)

    open_ports = run_scan(
        host=target,
        ports=ports,
        timeout=args.timeout,
        max_workers=args.threads,
        progress_callback=on_progress,
    )

    duration = time.perf_counter() - start

    # ── Analyze ───────────────────────────────────────────────────────────────
    report = analyze(
        target=target,
        open_ports=open_ports,
        ports_scanned=len(ports),
        scan_duration=duration,
    )

    # ── Print findings ────────────────────────────────────────────────────────
    print_section(f"Results  —  {report.open_ports} open port(s) found")

    if not report.findings:
        print(f"\n  {C.GREEN}No risky ports detected in this scan.{C.RESET}")
    else:
        from core.analyzer import RISK_ORDER
        grouped = report.findings_by_risk
        for risk_level in RISK_ORDER:
            for finding in grouped[risk_level]:
                print_finding(finding)

    # ── Score ─────────────────────────────────────────────────────────────────
    print_section("Security Score")
    print_score(report.security_score, report.grade)
    print(f"\n  {C.GRAY}{report.summary}{C.RESET}")

    # ── Scan stats ────────────────────────────────────────────────────────────
    print_section("Scan Statistics")
    print(f"  Ports scanned  : {len(ports):,}")
    print(f"  Open ports     : {report.open_ports}")
    print(f"  Scan duration  : {report.scan_duration}s")
    print(f"  Scan time      : {report.scan_time}")

    # ── HTML report ───────────────────────────────────────────────────────────
    if not args.no_report:
        os.makedirs("reports", exist_ok=True)
        if args.output:
            out_path = args.output
        else:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_target = target.replace(".", "_").replace(":", "_")
            out_path = f"reports/netaudit_{safe_target}_{ts}.html"

        generate_html(report, out_path)
        print(f"\n  {C.GREEN}✓ HTML report saved:{C.RESET} {C.BOLD}{out_path}{C.RESET}")

    print(f"\n{C.GRAY}  NetAudit complete. For educational and authorized use only.{C.RESET}\n")


if __name__ == "__main__":
    main()
