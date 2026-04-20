"""
SSL/TLS Certificate Checker Module
"""
import ssl
import socket
import hashlib
from datetime import datetime, timezone


def get_ssl_info(hostname: str, port: int = 443) -> dict:
    """Retrieve and analyze SSL/TLS certificate information."""
    result = {
        "success": False,
        "hostname": hostname,
        "port": port,
        "findings": [],
        "certificate": {},
        "tls_info": {},
        "severity_count": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    }

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
                cipher = ssock.cipher()

                # Parse certificate dates
                not_before_str = cert.get("notBefore", "")
                not_after_str = cert.get("notAfter", "")
                not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (not_after - now).days

                # SHA-256 fingerprint
                sha256 = hashlib.sha256(cert_der).hexdigest()
                fingerprint = ":".join(sha256[i:i+2].upper() for i in range(0, len(sha256), 2))

                # Subject / Issuer
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                san = [v for _, v in cert.get("subjectAltName", [])]

                result["certificate"] = {
                    "subject_cn": subject.get("commonName", "N/A"),
                    "issuer_cn": issuer.get("commonName", "N/A"),
                    "issuer_org": issuer.get("organizationName", "N/A"),
                    "not_before": not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "not_after": not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "days_remaining": days_left,
                    "san": san,
                    "sha256_fingerprint": fingerprint,
                    "serial_number": cert.get("serialNumber", "N/A"),
                    "version": cert.get("version", "N/A"),
                }

                result["tls_info"] = {
                    "protocol": tls_version,
                    "cipher_suite": cipher[0] if cipher else "N/A",
                    "cipher_bits": cipher[2] if cipher else "N/A",
                }

                # --- Security Checks ---
                findings = []

                # Expired
                if days_left < 0:
                    findings.append({
                        "type": "Certificate Expired",
                        "severity": "CRITICAL",
                        "detail": f"Certificate expired {abs(days_left)} days ago.",
                        "remediation": "Renew the SSL certificate immediately.",
                    })

                # Expiring soon
                elif days_left < 14:
                    findings.append({
                        "type": "Certificate Expiring Soon",
                        "severity": "HIGH",
                        "detail": f"Certificate expires in {days_left} days.",
                        "remediation": "Renew the certificate before expiry.",
                    })
                elif days_left < 30:
                    findings.append({
                        "type": "Certificate Expiring",
                        "severity": "MEDIUM",
                        "detail": f"Certificate expires in {days_left} days.",
                        "remediation": "Plan certificate renewal soon.",
                    })

                # Hostname mismatch
                valid_names = san + [subject.get("commonName", "")]
                hostname_match = any(
                    hostname == name or (name.startswith("*.") and hostname.endswith(name[1:]))
                    for name in valid_names
                )
                if not hostname_match:
                    findings.append({
                        "type": "Hostname Mismatch",
                        "severity": "HIGH",
                        "detail": f"Certificate CN/SAN does not match '{hostname}'.",
                        "remediation": "Obtain a certificate valid for this hostname.",
                    })

                # Weak TLS version
                if tls_version in ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"):
                    findings.append({
                        "type": "Weak TLS Protocol",
                        "severity": "HIGH",
                        "detail": f"Server is using deprecated {tls_version}.",
                        "remediation": "Disable TLS 1.0/1.1. Use TLS 1.2 or TLS 1.3 only.",
                    })

                # Weak cipher
                cipher_name = cipher[0] if cipher else ""
                if any(w in cipher_name.upper() for w in ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5")):
                    findings.append({
                        "type": "Weak Cipher Suite",
                        "severity": "HIGH",
                        "detail": f"Weak cipher in use: {cipher_name}",
                        "remediation": "Disable weak ciphers. Use AES-GCM, ChaCha20.",
                    })

                # Self-signed check
                if subject.get("commonName") == issuer.get("commonName"):
                    findings.append({
                        "type": "Self-Signed Certificate",
                        "severity": "MEDIUM",
                        "detail": "Certificate is self-signed and will not be trusted by browsers.",
                        "remediation": "Obtain a certificate from a trusted CA (e.g., Let's Encrypt).",
                    })

                # Short key (heuristic)
                bits = cipher[2] if cipher else 256
                if bits and bits < 128:
                    findings.append({
                        "type": "Short Encryption Key",
                        "severity": "HIGH",
                        "detail": f"Cipher key length is only {bits} bits.",
                        "remediation": "Use cipher suites with at least 128-bit keys.",
                    })

                if not findings:
                    findings.append({
                        "type": "Certificate OK",
                        "severity": "INFO",
                        "detail": f"Certificate is valid for {days_left} more days.",
                        "remediation": "",
                    })

                # Count severities
                for f in findings:
                    sev = f.get("severity", "INFO")
                    result["severity_count"][sev] = result["severity_count"].get(sev, 0) + 1

                result["findings"] = findings
                result["success"] = True
                result["scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    except ssl.SSLError as e:
        result["error"] = f"SSL Error: {str(e)}"
        result["findings"].append({
            "type": "SSL Handshake Failed",
            "severity": "CRITICAL",
            "detail": str(e),
            "remediation": "Check server SSL configuration.",
        })
    except socket.timeout:
        result["error"] = "Connection timed out."
    except ConnectionRefusedError:
        result["error"] = f"Connection refused on port {port}."
    except Exception as e:
        result["error"] = str(e)

    return result
