"""
NetAudit  |  core/utils.py
Terminal colors and pretty-print helpers.
"""

import sys
import os


# ── ANSI colors (auto-disabled if not a tty or on Windows without ANSI) ───────

USE_COLOR = sys.stdout.isatty() and os.name != "nt" or os.environ.get("FORCE_COLOR")

class C:
    RESET   = "\033[0m"  if USE_COLOR else ""
    BOLD    = "\033[1m"  if USE_COLOR else ""
    DIM     = "\033[2m"  if USE_COLOR else ""
    RED     = "\033[91m" if USE_COLOR else ""
    ORANGE  = "\033[33m" if USE_COLOR else ""
    YELLOW  = "\033[93m" if USE_COLOR else ""
    GREEN   = "\033[92m" if USE_COLOR else ""
    BLUE    = "\033[94m" if USE_COLOR else ""
    CYAN    = "\033[96m" if USE_COLOR else ""
    WHITE   = "\033[97m" if USE_COLOR else ""
    GRAY    = "\033[90m" if USE_COLOR else ""


RISK_COLORS = {
    "CRITICAL": C.RED,
    "HIGH":     C.ORANGE,
    "MEDIUM":   C.YELLOW,
    "LOW":      C.GREEN,
    "INFO":     C.BLUE,
}


def risk_colored(risk: str) -> str:
    color = RISK_COLORS.get(risk, C.WHITE)
    return f"{color}{C.BOLD}{risk:8}{C.RESET}"


def print_banner():
    print(f"""
{C.BLUE}{C.BOLD}
  ███╗   ██╗███████╗████████╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
  ██╔██╗ ██║█████╗     ██║   ███████║██║   ██║██║  ██║██║   ██║
  ██║╚██╗██║██╔══╝     ██║   ██╔══██║██║   ██║██║  ██║██║   ██║
  ██║ ╚████║███████╗   ██║   ██║  ██║╚██████╔╝██████╔╝██║   ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
{C.RESET}{C.GRAY}  Network Security Scanner & Risk Auditor  |  v1.0  |  by Daksh Shah{C.RESET}
{C.GRAY}  For educational and authorized security testing only.{C.RESET}
""")


def print_section(title: str):
    width = 60
    print(f"\n{C.BOLD}{C.WHITE}{'─' * width}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  {title}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}{'─' * width}{C.RESET}")


def print_finding(finding):
    risk_str = risk_colored(finding.risk)
    enc = f"{C.GREEN}🔒 Encrypted{C.RESET}" if finding.encrypted else f"{C.RED}🔓 Plaintext{C.RESET}"
    banner_str = f"  {C.GRAY}Banner: {finding.banner}{C.RESET}" if finding.banner else ""

    print(f"\n  {C.BOLD}{C.WHITE}Port {finding.port:>5}{C.RESET}  {C.CYAN}{finding.service:<16}{C.RESET}  {risk_str}  {enc}  {C.GRAY}{finding.latency}ms{C.RESET}")
    print(f"  {C.GRAY}{finding.description}{C.RESET}")
    print(f"  {C.BLUE}→ {finding.recommendation}{C.RESET}")
    if banner_str:
        print(banner_str)


def progress_bar(done: int, total: int, width: int = 40):
    pct  = done / total if total else 0
    fill = int(width * pct)
    bar  = f"{C.BLUE}{'█' * fill}{'░' * (width - fill)}{C.RESET}"
    sys.stdout.write(f"\r  Scanning  [{bar}] {done}/{total} ports ({pct:.0%})")
    sys.stdout.flush()
    if done == total:
        sys.stdout.write("\n")
        sys.stdout.flush()


def print_score(score: int, grade: str):
    if score >= 90:   color = C.GREEN
    elif score >= 75: color = C.BLUE
    elif score >= 60: color = C.YELLOW
    elif score >= 45: color = C.ORANGE
    else:             color = C.RED

    bar_len = score // 5
    bar = f"{color}{'█' * bar_len}{'░' * (20 - bar_len)}{C.RESET}"
    print(f"\n  Security Score  [{bar}]  {color}{C.BOLD}{score}/100  Grade {grade}{C.RESET}")
