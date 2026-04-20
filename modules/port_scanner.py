import socket
import threading
import time
from datetime import datetime

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt2", 27017: "MongoDB", 5432: "PostgreSQL",
    6379: "Redis", 1521: "Oracle", 1433: "MSSQL", 5000: "Flask/UPnP",
    9200: "Elasticsearch", 2375: "Docker", 2376: "Docker-TLS",
}

RISK_LEVELS = {
    21: "HIGH", 23: "CRITICAL", 25: "MEDIUM", 80: "LOW", 110: "MEDIUM",
    111: "HIGH", 135: "HIGH", 139: "HIGH", 143: "MEDIUM", 443: "LOW",
    445: "CRITICAL", 1433: "HIGH", 1521: "HIGH", 2375: "CRITICAL",
    3306: "HIGH", 3389: "HIGH", 5432: "HIGH", 5900: "HIGH", 6379: "HIGH",
    8080: "LOW", 8443: "LOW", 9200: "HIGH", 22: "LOW", 53: "LOW",
    27017: "HIGH",
}

RISK_DESCRIPTIONS = {
    21: "FTP transmits data in cleartext — credentials can be intercepted.",
    22: "SSH is generally secure; ensure strong authentication is enforced.",
    23: "Telnet is highly insecure — all traffic is cleartext.",
    25: "Open SMTP relay may be exploited for spam/phishing.",
    53: "DNS exposure — check for zone transfer vulnerabilities.",
    80: "HTTP is unencrypted; sensitive data should use HTTPS.",
    110: "POP3 may transmit credentials in cleartext.",
    111: "RPC portmapper can expose internal services.",
    135: "MSRPC is a common attack vector in Windows environments.",
    139: "NetBIOS session service — legacy and often exploitable.",
    143: "IMAP may transmit credentials without encryption.",
    443: "HTTPS — ensure valid certificate and strong TLS configuration.",
    445: "SMB — commonly targeted by ransomware (EternalBlue/WannaCry).",
    1433: "MSSQL exposed to network — restrict access with firewall rules.",
    1521: "Oracle DB should not be publicly accessible.",
    2375: "Docker daemon without TLS — allows full container control.",
    3306: "MySQL exposed — enforce authentication and network restrictions.",
    3389: "RDP is a prime target for brute force and exploitation.",
    5432: "PostgreSQL exposed — restrict access to trusted hosts.",
    5900: "VNC may use weak authentication.",
    6379: "Redis often runs without authentication — highly vulnerable.",
    8080: "HTTP alternative port — verify security configuration.",
    8443: "HTTPS alternative port — verify TLS configuration.",
    9200: "Elasticsearch may expose sensitive data without authentication.",
    27017: "MongoDB often accessible without authentication.",
}


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """Attempt TCP connection to a single port."""
    result = {
        "port": port,
        "service": COMMON_PORTS.get(port, "Unknown"),
        "state": "closed",
        "risk": "INFO",
        "description": "",
        "banner": "",
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            conn = s.connect_ex((host, port))
            if conn == 0:
                result["state"] = "open"
                result["risk"] = RISK_LEVELS.get(port, "INFO")
                result["description"] = RISK_DESCRIPTIONS.get(port, "Service is open.")
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                    result["banner"] = banner[:200] if banner else ""
                except Exception:
                    pass
    except Exception:
        pass
    return result


def resolve_host(target: str) -> dict:
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(target)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = target
        return {"success": True, "ip": ip, "hostname": hostname}
    except socket.gaierror as e:
        return {"success": False, "error": str(e)}


def run_port_scan(target: str, port_range: str = "common", custom_ports: list = None,
                  callback=None) -> dict:
    """
    Run a threaded port scan.
    port_range: 'common' | 'top100' | 'full' | 'custom'
    """
    start_time = time.time()
    resolution = resolve_host(target)
    if not resolution["success"]:
        return {"success": False, "error": f"Cannot resolve host: {resolution['error']}"}

    ip = resolution["ip"]
    hostname = resolution["hostname"]

    if port_range == "common":
        ports = list(COMMON_PORTS.keys())
    elif port_range == "top100":
        ports = list(range(1, 101))
    elif port_range == "full":
        ports = list(range(1, 1025))
    elif port_range == "custom" and custom_ports:
        ports = custom_ports
    else:
        ports = list(COMMON_PORTS.keys())

    open_ports = []
    closed_ports = []
    lock = threading.Lock()
    threads = []

    def worker(port):
        result = scan_port(ip, port)
        with lock:
            if result["state"] == "open":
                open_ports.append(result)
                if callback:
                    callback("port_found", result)
            else:
                closed_ports.append(result)

    for port in ports:
        t = threading.Thread(target=worker, args=(port,))
        threads.append(t)
        t.start()
        if len(threads) % 100 == 0:
            for th in threads[-100:]:
                th.join()

    for t in threads:
        t.join()

    elapsed = round(time.time() - start_time, 2)
    open_ports.sort(key=lambda x: x["port"])

    risk_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for p in open_ports:
        risk_summary[p["risk"]] = risk_summary.get(p["risk"], 0) + 1

    return {
        "success": True,
        "target": target,
        "ip": ip,
        "hostname": hostname,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed": elapsed,
        "total_ports_scanned": len(ports),
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "closed_count": len(closed_ports),
        "risk_summary": risk_summary,
        "port_range": port_range,
    }
