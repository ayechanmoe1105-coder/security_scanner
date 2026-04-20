"""
DNS Reconnaissance Module
"""
import socket
import dns.resolver
import dns.reversename
import whois
from datetime import datetime


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "admin", "vpn", "dev", "staging", "api", "app", "portal",
    "remote", "secure", "m", "mobile", "test", "git", "cdn", "cloud",
    "shop", "blog", "forum", "support", "docs", "wiki", "jira", "gitlab",
    "jenkins", "monitor", "status", "beta", "demo", "old", "backup",
]


def resolve_record(domain: str, record_type: str) -> list:
    """Resolve a specific DNS record type."""
    results = []
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=3)
        for rdata in answers:
            results.append(str(rdata))
    except Exception:
        pass
    return results


def subdomain_enum(domain: str, callback=None) -> list:
    """Enumerate common subdomains by brute-force DNS lookup."""
    found = []
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            entry = {"subdomain": fqdn, "ip": ip}
            found.append(entry)
            if callback:
                callback("subdomain_found", entry)
        except Exception:
            pass
    return found


def get_whois_info(domain: str) -> dict:
    """Perform a WHOIS lookup."""
    try:
        w = whois.whois(domain)
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        return {
            "registrar": w.registrar or "N/A",
            "creation_date": str(creation)[:19] if creation else "N/A",
            "expiry_date": str(expiry)[:19] if expiry else "N/A",
            "name_servers": w.name_servers or [],
            "status": w.status or [],
            "emails": w.emails or [],
            "country": w.country or "N/A",
            "org": w.org or "N/A",
        }
    except Exception as e:
        return {"error": str(e)}


def check_zone_transfer(domain: str) -> dict:
    """Attempt DNS zone transfer (AXFR) — should be refused."""
    result = {"vulnerable": False, "ns_servers": [], "records": []}
    try:
        ns_records = resolve_record(domain, "NS")
        result["ns_servers"] = ns_records
        for ns in ns_records:
            ns_ip = socket.gethostbyname(ns.rstrip("."))
            try:
                import dns.zone
                z = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, domain, timeout=3, lifetime=5)
                )
                result["vulnerable"] = True
                for name, node in z.nodes.items():
                    result["records"].append(str(name))
                break
            except Exception:
                pass
    except Exception:
        pass
    return result


def run_dns_recon(domain: str, enumerate_subdomains: bool = True,
                  callback=None) -> dict:
    """Full DNS reconnaissance."""
    # Strip protocol if provided
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    records = {}
    for rtype in RECORD_TYPES:
        data = resolve_record(domain, rtype)
        if data:
            records[rtype] = data

    # Zone transfer check
    zone_transfer = check_zone_transfer(domain)

    # WHOIS
    if callback:
        callback("status", "Performing WHOIS lookup...")
    whois_data = get_whois_info(domain)

    # Subdomain enumeration
    subdomains = []
    if enumerate_subdomains:
        if callback:
            callback("status", "Enumerating subdomains...")
        subdomains = subdomain_enum(domain, callback)

    # Security findings
    findings = []
    if zone_transfer["vulnerable"]:
        findings.append({
            "type": "DNS Zone Transfer Allowed",
            "severity": "HIGH",
            "detail": "AXFR zone transfer succeeded — full DNS zone is exposed.",
            "remediation": "Restrict zone transfers to authorized secondary DNS servers only.",
        })

    txt_records = records.get("TXT", [])
    spf = any("v=spf1" in t for t in txt_records)
    dmarc = resolve_record(f"_dmarc.{domain}", "TXT")
    dkim_hint = resolve_record(f"default._domainkey.{domain}", "TXT")

    if not spf:
        findings.append({
            "type": "Missing SPF Record",
            "severity": "MEDIUM",
            "detail": "No SPF TXT record found. Domain may be used for email spoofing.",
            "remediation": 'Add an SPF record, e.g., "v=spf1 include:_spf.google.com ~all"',
        })
    if not dmarc:
        findings.append({
            "type": "Missing DMARC Record",
            "severity": "MEDIUM",
            "detail": "No DMARC policy found. Phishing/spoofing may not be detected.",
            "remediation": 'Add a DMARC TXT record at _dmarc.domain.',
        })

    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        severity_count[sev] = severity_count.get(sev, 0) + 1

    return {
        "success": True,
        "domain": domain,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dns_records": records,
        "whois": whois_data,
        "subdomains": subdomains,
        "zone_transfer": zone_transfer,
        "findings": findings,
        "severity_count": severity_count,
        "spf_found": spf,
        "dmarc_found": bool(dmarc),
    }
