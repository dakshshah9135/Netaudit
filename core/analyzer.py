"""
NetAudit  |  core/analyzer.py
Maps open ports to risk levels and produces a scored audit report.
"""

import json
import socket
import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from core.scanner import PortResult


# ── Load risk database ────────────────────────────────────────────────────────

_DB_PATH = Path(__file__).parent.parent / "config" / "risk_db.json"

with open(_DB_PATH) as f:
    _DB = json.load(f)

PORT_DB     = _DB["ports"]
RISK_SCORES = _DB["risk_scores"]
RISK_COLORS = _DB["risk_colors"]

RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ── Data containers ───────────────────────────────────────────────────────────

@dataclass
class PortFinding:
    port:           int
    service:        str
    risk:           str
    encrypted:      bool
    description:    str
    recommendation: str
    banner:         Optional[str]
    latency:        float
    known:          bool   # True if port is in our risk DB


@dataclass
class AuditReport:
    target:         str
    ip_address:     str
    scan_time:      str
    scan_duration:  float        # seconds
    ports_scanned:  int
    open_ports:     int
    findings:       list[PortFinding] = field(default_factory=list)
    security_score: int = 100    # starts at 100, deducted per finding
    grade:          str = "A"
    summary:        str = ""

    @property
    def findings_by_risk(self) -> dict:
        grouped = {r: [] for r in RISK_ORDER}
        for f in self.findings:
            grouped[f.risk].append(f)
        return grouped

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == "HIGH")


# ── Core analysis ─────────────────────────────────────────────────────────────

def analyze(
    target: str,
    open_ports: list[PortResult],
    ports_scanned: int,
    scan_duration: float
) -> AuditReport:
    """
    Takes scan results and returns a fully populated AuditReport.
    """

    # Resolve IP
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        ip = target

    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = AuditReport(
        target=target,
        ip_address=ip,
        scan_time=scan_time,
        scan_duration=round(scan_duration, 2),
        ports_scanned=ports_scanned,
        open_ports=len(open_ports),
    )

    score = 100

    for result in open_ports:
        key = str(result.port)
        if key in PORT_DB:
            entry = PORT_DB[key]
            finding = PortFinding(
                port=result.port,
                service=entry["service"],
                risk=entry["risk"],
                encrypted=entry["encrypted"],
                description=entry["description"],
                recommendation=entry["recommendation"],
                banner=result.banner,
                latency=result.latency,
                known=True,
            )
            score -= RISK_SCORES.get(entry["risk"], 5)
        else:
            # Unknown port — flag as informational
            finding = PortFinding(
                port=result.port,
                service="Unknown",
                risk="INFO",
                encrypted=False,
                description=f"Port {result.port} is open but not in the known-risk database. Manual review recommended.",
                recommendation="Identify the service running on this port and assess if it should be publicly accessible.",
                banner=result.banner,
                latency=result.latency,
                known=False,
            )
            score -= 2   # small penalty for unknown open ports

        report.findings.append(finding)

    # Clamp score
    report.security_score = max(0, score)

    # Assign grade
    s = report.security_score
    if s >= 90:   report.grade = "A"
    elif s >= 75: report.grade = "B"
    elif s >= 60: report.grade = "C"
    elif s >= 45: report.grade = "D"
    else:         report.grade = "F"

    # Human-readable summary
    critical = report.critical_count
    high     = report.high_count

    if not report.findings:
        report.summary = "No commonly known risky ports were detected. The target appears well-hardened for standard port exposures. Consider a deeper vulnerability scan."
    elif critical > 0:
        report.summary = (
            f"⚠️  {critical} CRITICAL risk(s) detected — immediate action required. "
            f"Exposed critical services represent severe security risks including potential "
            f"remote code execution, unauthorized data access, or active exploitation vectors."
        )
    elif high > 0:
        report.summary = (
            f"{high} HIGH risk port(s) detected. Unencrypted or high-value services are "
            f"exposed. Review recommendations and remediate promptly to reduce attack surface."
        )
    else:
        report.summary = (
            f"{len(report.findings)} open port(s) detected with low-to-medium risk. "
            f"No critical exposures found. Review recommendations to further harden the target."
        )

    return report
