# VAPT — Vulnerability Assessment & Penetration Testing Platform

A professional-grade security assessment platform built with Python (Flask) and a modern dark-themed UI.

## ⚠️ Legal Disclaimer

**This tool is intended for authorized security testing ONLY.**
- Only use on systems you own or have explicit written permission to test.
- Unauthorized scanning is illegal and may violate the CFAA, GDPR, and other laws.
- The developers assume no liability for misuse.

---

## Features

| Module | Description |
|--------|-------------|
| **Port Scanner** | TCP port scanning with service fingerprinting and risk assessment |
| **Vulnerability Assessment** | CVE matching (EternalBlue, BlueKeep, WannaCry, etc.) |
| **Web App Scanner** | SQL Injection, XSS, missing security headers, sensitive file exposure (OWASP Top 10) |
| **SSL/TLS Analyzer** | Certificate validity, weak ciphers, TLS version, expiry alerts |
| **DNS Reconnaissance** | DNS records, subdomain enumeration, SPF/DMARC checks, zone transfer |
| **PDF/JSON Reports** | Professional security reports with remediation guidance |

## Installation

### Prerequisites
- Python 3.8+
- pip

### Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

Open your browser and navigate to: **http://127.0.0.1:5000**

## Usage

### Quick Scan (Dashboard)
1. Go to the Dashboard
2. Enter a target (IP / hostname / URL)
3. Select scan type
4. Click **Start Scan**

### Full Scan (Scanner Page)
1. Go to **Scanner** from the sidebar
2. Choose a scan mode: Port / Web / SSL / DNS / Full VAPT
3. Enter target and configure options
4. Click **Start Scan**
5. View real-time results and download PDF/JSON report

### Scan Types

| Mode | Target Format | Example |
|------|---------------|---------|
| Port Scan | IP or hostname | `192.168.1.1` |
| Web Scan | Full URL | `http://testphp.vulnweb.com` |
| SSL Check | Hostname | `example.com` |
| DNS Recon | Domain | `example.com` |
| Full VAPT | Any | `example.com` |

## Project Structure

```
ACM-prof/
├── app.py                    # Flask main application
├── requirements.txt
├── modules/
│   ├── port_scanner.py       # TCP port scanner
│   ├── vuln_scanner.py       # CVE-based vulnerability assessment
│   ├── web_scanner.py        # Web application scanner (OWASP)
│   ├── ssl_checker.py        # SSL/TLS certificate analyzer
│   ├── dns_recon.py          # DNS reconnaissance
│   └── report_generator.py  # PDF & JSON report generator
├── templates/
│   ├── base.html             # Base layout with sidebar
│   ├── index.html            # Dashboard
│   ├── scanner.html          # Scanner interface
│   ├── history.html          # Scan history
│   └── reports.html          # Report generation
├── static/
│   ├── css/style.css         # UI stylesheet
│   └── js/main.js            # Global JavaScript
└── reports/                  # Generated reports (auto-created)
```

## Safe Test Targets

These are publicly available targets for legal security testing:

- `testphp.vulnweb.com` — Acunetix test site
- `scanme.nmap.org` — Nmap's official test server
- `demo.testfire.net` — IBM AltoroMutual demo bank
- Your own local VMs or lab environments

## Tech Stack

- **Backend**: Python 3, Flask, Flask-SocketIO
- **Frontend**: HTML5, CSS3, JavaScript, Chart.js
- **Libraries**: Requests, BeautifulSoup4, dnspython, pyOpenSSL, fpdf2, python-whois
