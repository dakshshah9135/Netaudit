# 🛡️ NetAudit — Network Security Scanner & Risk Auditor

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-red)

A fast, multi-threaded **network security scanner** that checks open ports, detects unencrypted/risky services, and generates a professional **HTML risk report** with a scored security grade.

> ⚠️ **Ethical Use Only** — Only scan systems you own or have explicit written permission to scan. Unauthorized port scanning may be illegal in your jurisdiction.

---

## 📸 Features

- ⚡ **Multi-threaded** — Scans 150 ports in parallel (configurable)
- 🔍 **Banner Grabbing** — Identifies service versions from live banners
- 🧠 **Risk Intelligence** — 30+ ports mapped to CVE-backed risk levels (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- 📊 **Security Scoring** — 0–100 score with letter grade (A–F)
- 📄 **HTML Report** — Clean, dark-themed, self-contained report with per-port remediation guidance
- 🖥️ **Rich CLI** — Color-coded terminal output with live progress bar
- 🔒 **Encryption Detection** — Flags plaintext-protocol exposures (FTP, Telnet, HTTP, etc.)

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10 or higher
- No third-party packages required (pure standard library)

### Installation

```bash
# Clone the repository
git clone https://github.com/daksh-shah9135/netaudit.git
cd netaudit
```

### Usage

```bash
# Quick scan — 43 most security-relevant ports
python netaudit.py scanme.nmap.org

# Full scan — ports 1-1024 + all known-risk ports
python netaudit.py 192.168.1.1 --full

# Specific ports
python netaudit.py 10.0.0.1 --ports 22,80,443,3306,8080

# Custom output file
python netaudit.py target.com --output my_report.html

# Adjust timeout (useful for slow networks)
python netaudit.py target.com --timeout 2.0

# Terminal output only, skip HTML report
python netaudit.py target.com --no-report
```

---

## 📊 Risk Levels

| Level    | Color  | Examples                              | Action          |
|----------|--------|---------------------------------------|-----------------|
| CRITICAL | 🔴 Red | Telnet, SMB (445), Redis, RDP, MongoDB | Immediate fix   |
| HIGH     | 🟠 Orange | FTP, POP3, IMAP, MSRPC, NetBIOS     | Fix promptly    |
| MEDIUM   | 🟡 Yellow | HTTP, SMTP, DNS                     | Review & harden |
| LOW      | 🟢 Green | SSH, HTTPS-Alt                       | Harden config   |
| INFO     | 🔵 Blue | HTTPS (443), Unknown ports            | Verify & monitor|

---

## 📁 Project Structure

```
NetAudit/
├── netaudit.py          # Main CLI entry point
├── requirements.txt     # Dependencies (stdlib only)
├── README.md
├── core/
│   ├── scanner.py       # Multi-threaded TCP scanner + banner grabbing
│   ├── analyzer.py      # Risk mapping & security scoring engine
│   ├── reporter.py      # HTML report generator
│   └── utils.py         # CLI colors, progress bar, formatting
├── config/
│   └── risk_db.json     # Port → risk intelligence database (30+ entries)
└── reports/             # Generated HTML reports saved here
```

---

## 🧪 Test on Legal Targets

These hosts are **legally sanctioned** for scanning practice:

```bash
python netaudit.py scanme.nmap.org        # Nmap's official test host
python netaudit.py testphp.vulnweb.com    # Acunetix test site
```

---

## 📖 How It Works

```
Target Input
    │
    ▼
Port Scanner (multi-threaded TCP connect + banner grab)
    │
    ▼
Risk Analyzer (maps ports → risk DB → calculates score)
    │
    ▼
Terminal Output (colored, real-time)
    │
    ▼
HTML Report (self-contained, dark-themed, with remediation)
```

1. **Scanner** — Opens `N` threads simultaneously, each attempting a TCP handshake. On success, sends a protocol-appropriate probe to grab the service banner.
2. **Analyzer** — Looks up each open port in `config/risk_db.json`, assigns a risk level, deducts from the security score, and builds the audit report object.
3. **Reporter** — Renders a fully self-contained HTML file with the findings table, severity summary, score gauge, and per-port remediation advice.

---

## 🔮 Planned Features

- [ ] JSON export for integration with SIEM tools
- [ ] CVE cross-reference for detected service versions
- [ ] IP reputation lookup (AbuseIPDB API integration)
- [ ] UDP port scanning
- [ ] OS fingerprinting via TTL analysis
- [ ] Scheduled scan + email alerts

---

## 👤 Author

**Daksh Shah**
B.Tech Cybersecurity Student — Shah & Anchor Kutchhi Engineering College, Mumbai

[![LinkedIn](https://img.shields.io/badge/LinkedIn-daksh--shah9135-blue?logo=linkedin)](https://linkedin.com/in/daksh-shah9135)
[![Email](https://img.shields.io/badge/Email-dakshshah9135%40gmail.com-red?logo=gmail)](mailto:dakshshah9135@gmail.com)

---

## ⚖️ License

MIT License — see [LICENSE](LICENSE) for details.

**This tool is for educational purposes and authorized security testing only. The author assumes no liability for misuse.**
