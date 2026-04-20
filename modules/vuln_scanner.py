"""
Vulnerability Scanner Module
Checks for known CVEs and misconfigurations based on open service fingerprints.
"""
import requests
import socket
import ssl
from datetime import datetime

KNOWN_VULNERABILITIES = {
    "FTP": [
        {
            "cve": "CVE-2011-2523",
            "name": "vsftpd 2.3.4 Backdoor",
            "severity": "CRITICAL",
            "cvss": 10.0,
            "description": "vsftpd 2.3.4 contains a backdoor that opens a shell on port 6200.",
            "remediation": "Upgrade vsftpd to a patched version immediately.",
        },
        {
            "cve": "CVE-1999-0497",
            "name": "Anonymous FTP Enabled",
            "severity": "HIGH",
            "cvss": 7.5,
            "description": "Anonymous FTP access allows unauthenticated users to read/write files.",
            "remediation": "Disable anonymous FTP access or restrict permissions.",
        },
    ],
    "Telnet": [
        {
            "cve": "CVE-2011-4862",
            "name": "Telnet Cleartext Transmission",
            "severity": "CRITICAL",
            "cvss": 10.0,
            "description": "Telnet transmits all data including credentials in cleartext.",
            "remediation": "Disable Telnet and use SSH instead.",
        },
    ],
    "SMB": [
        {
            "cve": "CVE-2017-0144",
            "name": "EternalBlue / MS17-010",
            "severity": "CRITICAL",
            "cvss": 9.3,
            "description": "SMBv1 vulnerability exploited by WannaCry and NotPetya ransomware.",
            "remediation": "Apply MS17-010 patch. Disable SMBv1 and block port 445.",
        },
        {
            "cve": "CVE-2020-0796",
            "name": "SMBGhost / CoronaBlue",
            "severity": "CRITICAL",
            "cvss": 10.0,
            "description": "Buffer overflow in SMBv3 compression allows remote code execution.",
            "remediation": "Apply Microsoft patch KB4551762. Disable SMBv3 compression.",
        },
    ],
    "RDP": [
        {
            "cve": "CVE-2019-0708",
            "name": "BlueKeep",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "Pre-auth RCE in RDP — allows wormable exploitation without credentials.",
            "remediation": "Patch immediately. Enable NLA. Restrict RDP access with firewall.",
        },
        {
            "cve": "CVE-2019-1182",
            "name": "DejaBlue",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "Multiple RDP flaws allowing pre-authentication RCE.",
            "remediation": "Apply August 2019 Windows security updates.",
        },
    ],
    "MySQL": [
        {
            "cve": "CVE-2012-2122",
            "name": "MySQL Authentication Bypass",
            "severity": "HIGH",
            "cvss": 7.5,
            "description": "Race condition allows authentication bypass with random passwords.",
            "remediation": "Upgrade MySQL. Bind to localhost only.",
        },
    ],
    "Redis": [
        {
            "cve": "CVE-2022-0543",
            "name": "Redis Lua Sandbox Escape",
            "severity": "CRITICAL",
            "cvss": 10.0,
            "description": "Lua sandbox escape leads to remote code execution.",
            "remediation": "Upgrade Redis. Enable authentication. Restrict network access.",
        },
    ],
    "MongoDB": [
        {
            "cve": "CVE-2013-4650",
            "name": "MongoDB No Authentication",
            "severity": "HIGH",
            "cvss": 7.8,
            "description": "MongoDB running without authentication exposes all data.",
            "remediation": "Enable authentication. Bind to localhost. Use firewall rules.",
        },
    ],
    "MSRPC": [
        {
            "cve": "CVE-2003-0352",
            "name": "MS RPC DCOM Vulnerability",
            "severity": "HIGH",
            "cvss": 7.5,
            "description": "Buffer overflow in DCOM RPC allows remote code execution.",
            "remediation": "Apply Microsoft patches. Block port 135 at firewall.",
        },
    ],
    "HTTP": [
        {
            "cve": "GENERIC-HTTP-001",
            "name": "Unencrypted HTTP Traffic",
            "severity": "MEDIUM",
            "cvss": 5.0,
            "description": "HTTP traffic is not encrypted; susceptible to MITM attacks.",
            "remediation": "Redirect all HTTP to HTTPS. Use HSTS.",
        },
    ],
    "VNC": [
        {
            "cve": "CVE-2019-15694",
            "name": "LibVNCServer Heap Overflow",
            "severity": "HIGH",
            "cvss": 8.0,
            "description": "Heap overflow in LibVNCServer allows remote code execution.",
            "remediation": "Update VNC software. Use strong VNC passwords. Restrict access.",
        },
    ],
    "Docker-TLS": [
        {
            "cve": "CVE-2019-5736",
            "name": "runc Container Escape",
            "severity": "CRITICAL",
            "cvss": 8.6,
            "description": "Overwrite host runc binary from within a container.",
            "remediation": "Update Docker. Avoid privileged containers.",
        },
    ],
}

GENERIC_CHECKS = {
    "Telnet": {
        "check": "port_open",
        "message": "Telnet is enabled — all traffic is unencrypted.",
        "severity": "CRITICAL",
    },
    "FTP": {
        "check": "port_open",
        "message": "FTP is enabled — may transmit credentials in cleartext.",
        "severity": "HIGH",
    },
    "SMB": {
        "check": "port_open",
        "message": "SMB port open — verify patches for EternalBlue/WannaCry.",
        "severity": "CRITICAL",
    },
    "RDP": {
        "check": "port_open",
        "message": "RDP exposed — high-value target for brute force attacks.",
        "severity": "HIGH",
    },
    "Redis": {
        "check": "port_open",
        "message": "Redis port open — often runs without authentication.",
        "severity": "HIGH",
    },
    "MongoDB": {
        "check": "port_open",
        "message": "MongoDB port open — check if authentication is enabled.",
        "severity": "HIGH",
    },
}


def check_service_vulnerabilities(service: str) -> list:
    """Return known CVEs for a given service name."""
    return KNOWN_VULNERABILITIES.get(service, [])


def assess_open_ports(open_ports: list) -> dict:
    """
    Given a list of open port scan results, assess vulnerabilities.
    Returns structured vulnerability findings.
    """
    findings = []
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for port_info in open_ports:
        service = port_info.get("service", "Unknown")
        port = port_info.get("port", 0)

        vulns = check_service_vulnerabilities(service)
        for vuln in vulns:
            finding = {
                "port": port,
                "service": service,
                **vuln,
            }
            findings.append(finding)
            sev = vuln.get("severity", "INFO")
            severity_count[sev] = severity_count.get(sev, 0) + 1

    findings.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
                  .get(x["severity"], 5))

    overall_risk = "LOW"
    if severity_count["CRITICAL"] > 0:
        overall_risk = "CRITICAL"
    elif severity_count["HIGH"] > 0:
        overall_risk = "HIGH"
    elif severity_count["MEDIUM"] > 0:
        overall_risk = "MEDIUM"

    return {
        "findings": findings,
        "total_findings": len(findings),
        "severity_count": severity_count,
        "overall_risk": overall_risk,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def check_default_credentials(host: str, port: int, service: str) -> dict:
    """Check for common default credential usage (safe, non-destructive)."""
    results = []

    if service == "FTP":
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=3)
            try:
                ftp.login("anonymous", "anonymous@test.com")
                results.append({
                    "type": "Default Credentials",
                    "severity": "HIGH",
                    "detail": "Anonymous FTP login succeeded — no authentication required.",
                })
                ftp.quit()
            except ftplib.error_perm:
                pass
        except Exception:
            pass

    return {"service": service, "port": port, "results": results}
