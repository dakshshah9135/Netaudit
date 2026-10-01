"""
NetAudit  |  core/reporter.py
Generates a professional, self-contained HTML security report.
"""

import json
from pathlib import Path
from core.analyzer import AuditReport, RISK_COLORS, RISK_ORDER


def _risk_badge(risk: str) -> str:
    color = RISK_COLORS.get(risk, "#6b7280")
    return f'<span class="badge" style="background:{color}">{risk}</span>'


def _score_color(score: int) -> str:
    if score >= 90: return "#16a34a"
    if score >= 75: return "#2563eb"
    if score >= 60: return "#d97706"
    if score >= 45: return "#ea580c"
    return "#dc2626"


def _grade_color(grade: str) -> str:
    return {"A": "#16a34a", "B": "#2563eb", "C": "#d97706", "D": "#ea580c", "F": "#dc2626"}.get(grade, "#6b7280")


def generate_html(report: AuditReport, output_path: str) -> str:
    """Render the full HTML report and write to output_path. Returns the path."""

    rows = ""
    for finding in sorted(report.findings, key=lambda f: RISK_ORDER.index(f.risk)):
        enc_icon = "🔒" if finding.encrypted else "🔓"
        enc_text = "Encrypted" if finding.encrypted else "Plaintext"
        banner_html = f'<code class="banner">{finding.banner}</code>' if finding.banner else '<span class="na">—</span>'
        rows += f"""
        <tr>
          <td><strong>{finding.port}</strong></td>
          <td>{finding.service}</td>
          <td>{_risk_badge(finding.risk)}</td>
          <td>{enc_icon} {enc_text}</td>
          <td class="desc">{finding.description}</td>
          <td class="rec">{finding.recommendation}</td>
          <td>{banner_html}</td>
          <td>{finding.latency} ms</td>
        </tr>"""

    # Findings by severity summary bar
    counts = {r: 0 for r in RISK_ORDER}
    for f in report.findings:
        counts[f.risk] += 1

    severity_bars = ""
    for r in RISK_ORDER:
        c = counts[r]
        if c > 0:
            color = RISK_COLORS[r]
            severity_bars += f'<div class="sev-chip" style="border-left:4px solid {color}"><span class="sev-num" style="color:{color}">{c}</span><span class="sev-label">{r}</span></div>'

    score_color = _score_color(report.security_score)
    grade_color = _grade_color(report.grade)

    no_findings_msg = ""
    if not report.findings:
        no_findings_msg = '<tr><td colspan="8" style="text-align:center;padding:2rem;color:#6b7280;">No risky open ports detected in this scan.</td></tr>'
        rows = no_findings_msg

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>NetAudit Report — {report.target}</title>
<style>
  :root {{
    --bg: #0f172a; --card: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #3b82f6;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }}

  /* ── Header ── */
  .header {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%); padding: 2.5rem 3rem; border-bottom: 1px solid var(--border); }}
  .header-top {{ display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 1.5rem; }}
  .logo {{ display: flex; align-items: center; gap: 0.75rem; }}
  .logo-icon {{ width: 42px; height: 42px; background: #3b82f6; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.4rem; }}
  .logo-text {{ font-size: 1.5rem; font-weight: 800; color: #fff; letter-spacing: -0.5px; }}
  .logo-sub {{ font-size: 0.75rem; color: var(--muted); letter-spacing: 2px; text-transform: uppercase; }}
  .score-card {{ text-align: center; }}
  .score-num {{ font-size: 3.5rem; font-weight: 900; color: {score_color}; line-height: 1; }}
  .score-label {{ font-size: 0.7rem; color: var(--muted); text-transform: uppercase; letter-spacing: 2px; margin-top: 4px; }}
  .grade-badge {{ display: inline-block; padding: 0.2rem 0.9rem; background: {grade_color}22; color: {grade_color}; border: 1px solid {grade_color}; border-radius: 6px; font-size: 1.4rem; font-weight: 800; margin-top: 6px; }}

  /* ── Meta grid ── */
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-top: 2rem; }}
  .meta-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1rem 1.25rem; }}
  .meta-label {{ font-size: 0.68rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 6px; }}
  .meta-value {{ font-size: 1.05rem; font-weight: 600; color: var(--text); }}

  /* ── Summary ── */
  .summary-box {{ margin: 2rem 3rem; background: var(--card); border: 1px solid var(--border); border-left: 4px solid {score_color}; border-radius: 10px; padding: 1.25rem 1.5rem; font-size: 0.95rem; line-height: 1.6; }}

  /* ── Severity chips ── */
  .sev-row {{ display: flex; gap: 1rem; flex-wrap: wrap; padding: 0 3rem 1.5rem; }}
  .sev-chip {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 0.5rem 1rem; display: flex; flex-direction: column; align-items: center; min-width: 80px; }}
  .sev-num {{ font-size: 1.6rem; font-weight: 800; line-height: 1; }}
  .sev-label {{ font-size: 0.62rem; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-top: 2px; }}

  /* ── Table ── */
  .table-wrap {{ padding: 0 3rem 3rem; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.84rem; }}
  thead tr {{ background: #0f172a; }}
  th {{ padding: 0.75rem 1rem; text-align: left; color: var(--muted); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1.2px; border-bottom: 1px solid var(--border); white-space: nowrap; }}
  td {{ padding: 0.85rem 1rem; border-bottom: 1px solid #1e293b; vertical-align: top; }}
  tr:hover td {{ background: #1e293b55; }}
  .desc, .rec {{ max-width: 220px; line-height: 1.5; color: var(--muted); font-size: 0.82rem; }}
  .rec {{ color: #93c5fd; }}

  /* ── Badges ── */
  .badge {{ display: inline-block; padding: 0.2rem 0.65rem; border-radius: 5px; font-size: 0.7rem; font-weight: 700; color: #fff; letter-spacing: 0.5px; }}
  .banner {{ background: #0f172a; color: #67e8f9; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; word-break: break-all; }}
  .na {{ color: #475569; }}

  /* ── Footer ── */
  footer {{ text-align: center; padding: 1.5rem; color: var(--muted); font-size: 0.78rem; border-top: 1px solid var(--border); }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div class="logo">
      <div class="logo-icon">🛡️</div>
      <div>
        <div class="logo-text">NetAudit</div>
        <div class="logo-sub">Network Security Scanner</div>
      </div>
    </div>
    <div class="score-card">
      <div class="score-num">{report.security_score}</div>
      <div class="score-label">Security Score</div>
      <div class="grade-badge">Grade {report.grade}</div>
    </div>
  </div>

  <div class="meta-grid">
    <div class="meta-card">
      <div class="meta-label">Target</div>
      <div class="meta-value">{report.target}</div>
    </div>
    <div class="meta-card">
      <div class="meta-label">IP Address</div>
      <div class="meta-value">{report.ip_address}</div>
    </div>
    <div class="meta-card">
      <div class="meta-label">Scan Time</div>
      <div class="meta-value">{report.scan_time}</div>
    </div>
    <div class="meta-card">
      <div class="meta-label">Ports Scanned</div>
      <div class="meta-value">{report.ports_scanned:,}</div>
    </div>
    <div class="meta-card">
      <div class="meta-label">Open Ports Found</div>
      <div class="meta-value">{report.open_ports}</div>
    </div>
    <div class="meta-card">
      <div class="meta-label">Scan Duration</div>
      <div class="meta-value">{report.scan_duration}s</div>
    </div>
  </div>
</div>

<div class="summary-box">{report.summary}</div>

<div class="sev-row">{severity_bars}</div>

<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Port</th>
        <th>Service</th>
        <th>Risk Level</th>
        <th>Encryption</th>
        <th>Description</th>
        <th>Recommendation</th>
        <th>Banner</th>
        <th>Latency</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</div>

<footer>
  Generated by <strong>NetAudit v1.0</strong> &nbsp;|&nbsp;
  Built by <strong>Daksh Shah</strong> &nbsp;|&nbsp;
  <a href="https://github.com/daksh-shah9135/netaudit" target="_blank">github.com/daksh-shah9135/netaudit</a>
  &nbsp;|&nbsp; For educational and authorized security testing only.
</footer>

</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path
