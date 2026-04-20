"""
Web Application Scanner Module
Tests for common OWASP Top 10 vulnerabilities.
"""
import requests
import re
from urllib.parse import urljoin, urlparse, urlencode
from bs4 import BeautifulSoup
from datetime import datetime

requests.packages.urllib3.disable_warnings()

SQLI_PAYLOADS = [
    "'", "''", "`", "``", ",", '"', "\"\"", "/", "//", "\\", "//",
    "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
    "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    "admin'--", "admin' #", "admin'/*",
    "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
    "1' UNION SELECT null--", "1' UNION SELECT null,null--",
    "' AND 1=2 UNION SELECT 1,2,3--",
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySqlClient\.",
    r"PostgreSQL.*ERROR", r"Warning.*pg_.*", r"valid PostgreSQL result",
    r"Npgsql\.", r"PG::SyntaxError:", r"org\.postgresql\.util\.PSQLException",
    r"ERROR:\s\ssyntax error at or near",
    r"Microsoft OLE DB Provider for ODBC Drivers error",
    r"Microsoft OLE DB Provider for SQL Server",
    r"Unclosed quotation mark after the character string",
    r"\[Microsoft\]\[ODBC SQL Server Driver\]",
    r"ODBC SQL Server Driver", r"ODBC Driver \d+ for SQL Server",
    r"SQLServer JDBC Driver", r"com\.microsoft\.sqlserver\.jdbc",
    r"ORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver",
    r"Warning.*oci_.*", r"Warning.*ora_.*",
    r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]",
    r"Dynamic SQL Error", r"Warning.*ibase_.*", r"org\.hsqldb\.jdbc",
    r"Syntax error.*in query expression",
    r"Data type mismatch in criteria expression",
    r"\[Microsoft\]\[ODBC Microsoft Access Driver\]",
]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<body onload=alert(1)>',
    '<<SCRIPT>alert("XSS");//<</SCRIPT>',
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections (HSTS)",
        "severity": "HIGH",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "Content-Security-Policy": {
        "description": "Mitigates XSS and data injection attacks",
        "severity": "HIGH",
        "recommendation": "Define a strict Content-Security-Policy header.",
    },
    "X-XSS-Protection": {
        "description": "Activates browser's XSS filter (legacy)",
        "severity": "LOW",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent with requests",
        "severity": "LOW",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Controls browser feature permissions",
        "severity": "LOW",
        "recommendation": "Add a Permissions-Policy header restricting unused features.",
    },
}

SENSITIVE_PATHS = [
    "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.production",
    "/wp-config.php", "/config.php", "/config.yml", "/config.yaml",
    "/web.config", "/appsettings.json", "/application.properties",
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/phpinfo.php",
    "/info.php", "/server-status", "/server-info",
    "/admin", "/admin/", "/administrator", "/login", "/wp-admin",
    "/phpmyadmin", "/pma", "/dbadmin", "/mysqladmin",
    "/backup", "/backup.zip", "/backup.tar.gz", "/db.sql",
    "/api/v1", "/api/v2", "/swagger", "/swagger-ui.html",
    "/actuator", "/actuator/health", "/actuator/env",
    "/.DS_Store", "/thumbs.db",
]


def get_forms(url: str, session: requests.Session) -> list:
    """Extract all forms from a webpage."""
    try:
        resp = session.get(url, timeout=5, verify=False)
        soup = BeautifulSoup(resp.content, "lxml")
        return soup.find_all("form")
    except Exception:
        return []


def get_form_details(form) -> dict:
    """Extract form action, method, and inputs."""
    details = {"action": form.attrs.get("action", "").lower(),
               "method": form.attrs.get("method", "get").lower(),
               "inputs": []}
    for input_tag in form.find_all("input"):
        details["inputs"].append({
            "type": input_tag.attrs.get("type", "text"),
            "name": input_tag.attrs.get("name"),
            "value": input_tag.attrs.get("value", ""),
        })
    return details


def check_sqli(url: str, session: requests.Session) -> list:
    """Test URL parameters for SQL injection."""
    findings = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings

    params = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)
    for param in params:
        for payload in SQLI_PAYLOADS[:8]:
            test_params = params.copy()
            test_params[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
            try:
                resp = session.get(test_url, timeout=5, verify=False)
                for pattern in SQLI_ERROR_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        findings.append({
                            "type": "SQL Injection",
                            "severity": "CRITICAL",
                            "cvss": 9.8,
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": f"SQL error pattern detected: {pattern}",
                            "remediation": "Use parameterized queries/prepared statements. Never concatenate user input in SQL.",
                        })
                        break
            except Exception:
                pass
    return findings


def check_xss(url: str, session: requests.Session) -> list:
    """Test forms for reflected XSS."""
    findings = []
    forms = get_forms(url, session)
    for form in forms:
        details = get_form_details(form)
        for payload in XSS_PAYLOADS[:5]:
            data = {}
            for inp in details["inputs"]:
                if inp["type"] in ("text", "search", "email", "url", "hidden"):
                    data[inp["name"]] = payload
                elif inp["name"]:
                    data[inp["name"]] = inp["value"] or "test"
            action = urljoin(url, details["action"]) if details["action"] else url
            try:
                if details["method"] == "post":
                    resp = session.post(action, data=data, timeout=5, verify=False)
                else:
                    resp = session.get(action, params=data, timeout=5, verify=False)
                if payload in resp.text:
                    findings.append({
                        "type": "Cross-Site Scripting (XSS)",
                        "severity": "HIGH",
                        "cvss": 7.4,
                        "url": action,
                        "payload": payload,
                        "evidence": f"Payload reflected in response body.",
                        "remediation": "Encode all user-supplied output. Implement a strict Content-Security-Policy.",
                    })
                    break
            except Exception:
                pass
    return findings


def check_security_headers(url: str, session: requests.Session) -> list:
    """Check for missing security headers."""
    findings = []
    try:
        resp = session.get(url, timeout=5, verify=False)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        for header, info in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                findings.append({
                    "type": f"Missing Security Header: {header}",
                    "severity": info["severity"],
                    "cvss": 5.0 if info["severity"] == "HIGH" else 3.5,
                    "url": url,
                    "evidence": f"Header '{header}' is absent from the response.",
                    "description": info["description"],
                    "remediation": info["recommendation"],
                })
        # Check for information disclosure
        server = resp.headers.get("Server", "")
        x_powered = resp.headers.get("X-Powered-By", "")
        if server:
            findings.append({
                "type": "Server Version Disclosure",
                "severity": "LOW",
                "cvss": 2.6,
                "url": url,
                "evidence": f"Server header reveals: {server}",
                "remediation": "Remove or obscure the Server header to prevent version fingerprinting.",
            })
        if x_powered:
            findings.append({
                "type": "Technology Disclosure (X-Powered-By)",
                "severity": "LOW",
                "cvss": 2.6,
                "url": url,
                "evidence": f"X-Powered-By header reveals: {x_powered}",
                "remediation": "Remove the X-Powered-By header.",
            })
    except Exception as e:
        findings.append({"type": "Connection Error", "severity": "INFO",
                         "url": url, "evidence": str(e), "remediation": ""})
    return findings


def check_sensitive_paths(base_url: str, session: requests.Session,
                          callback=None) -> list:
    """Check for exposed sensitive files and directories."""
    findings = []
    for path in SENSITIVE_PATHS:
        url = urljoin(base_url, path)
        try:
            resp = session.get(url, timeout=4, verify=False, allow_redirects=False)
            if resp.status_code in (200, 206):
                severity = "CRITICAL" if path in ("/.git/config", "/.env",
                                                   "/wp-config.php") else "HIGH"
                finding = {
                    "type": "Sensitive File/Directory Exposed",
                    "severity": severity,
                    "cvss": 8.5 if severity == "CRITICAL" else 6.5,
                    "url": url,
                    "status_code": resp.status_code,
                    "evidence": f"HTTP {resp.status_code} — resource is accessible.",
                    "remediation": f"Restrict access to {path} via web server configuration.",
                }
                findings.append(finding)
                if callback:
                    callback("path_found", finding)
        except Exception:
            pass
    return findings


def run_web_scan(target_url: str, callback=None) -> dict:
    """
    Run a full web application vulnerability scan.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (VAPT-Scanner/1.0; Educational Use)"
    })

    all_findings = []
    scan_steps = []

    # 1. Security Headers
    if callback:
        callback("status", "Checking security headers...")
    header_findings = check_security_headers(target_url, session)
    all_findings.extend(header_findings)
    scan_steps.append({"step": "Security Headers", "count": len(header_findings)})

    # 2. SQLi
    if callback:
        callback("status", "Testing for SQL injection...")
    sqli_findings = check_sqli(target_url, session)
    all_findings.extend(sqli_findings)
    scan_steps.append({"step": "SQL Injection", "count": len(sqli_findings)})

    # 3. XSS
    if callback:
        callback("status", "Testing for XSS vulnerabilities...")
    xss_findings = check_xss(target_url, session)
    all_findings.extend(xss_findings)
    scan_steps.append({"step": "XSS", "count": len(xss_findings)})

    # 4. Sensitive paths
    if callback:
        callback("status", "Checking for exposed sensitive files...")
    path_findings = check_sensitive_paths(target_url, session, callback)
    all_findings.extend(path_findings)
    scan_steps.append({"step": "Sensitive Paths", "count": len(path_findings)})

    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        severity_count[sev] = severity_count.get(sev, 0) + 1

    overall_risk = "LOW"
    if severity_count["CRITICAL"] > 0:
        overall_risk = "CRITICAL"
    elif severity_count["HIGH"] > 0:
        overall_risk = "HIGH"
    elif severity_count["MEDIUM"] > 0:
        overall_risk = "MEDIUM"

    all_findings.sort(
        key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        .get(x.get("severity", "INFO"), 5)
    )

    return {
        "success": True,
        "target": target_url,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "findings": all_findings,
        "total_findings": len(all_findings),
        "severity_count": severity_count,
        "overall_risk": overall_risk,
        "scan_steps": scan_steps,
    }
