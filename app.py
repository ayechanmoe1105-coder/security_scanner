"""
VAPT - Vulnerability Assessment & Penetration Testing Platform
Main Flask Application
"""
import os
import socket
import threading
import time
import webbrowser
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit

from modules.port_scanner import run_port_scan
from modules.vuln_scanner import assess_open_ports
from modules.web_scanner import run_web_scan
from modules.ssl_checker import get_ssl_info
from modules.dns_recon import run_dns_recon
from modules.report_generator import generate_pdf_report, generate_json_report

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "vapt-dev-key-change-in-production")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# In-memory scan history
scan_history = []
active_scans = {}
_next_history_id = 1


def add_to_history(scan_type: str, target: str, result: dict):
    global _next_history_id
    entry = {
        "id": _next_history_id,
        "type": scan_type,
        "target": target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "overall_risk": result.get("overall_risk", "N/A"),
        "total_findings": result.get("total_findings", result.get("open_count", 0)),
        "result": result,
    }
    scan_history.insert(0, entry)
    _next_history_id += 1
    if len(scan_history) > 50:
        scan_history.pop()
    return entry


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scanner")
def scanner():
    return render_template("scanner.html")


@app.route("/reports-page")
def reports_page():
    return render_template("reports.html")


@app.route("/history-page")
def history_page():
    return render_template("history.html")


@app.route("/health")
def health():
    return jsonify(ok=True)


# ─── API: Port Scanner ────────────────────────────────────────────────────────

@app.route("/api/scan/ports", methods=["POST"])
def api_port_scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    port_range = data.get("port_range", "common")

    if not target:
        return jsonify({"success": False, "error": "Target is required."}), 400

    scan_id = f"port_{int(time.time())}"
    active_scans[scan_id] = {"status": "running", "start": time.time()}

    def callback(event, payload):
        socketio.emit("scan_event", {"scan_id": scan_id, "event": event,
                                     "data": payload})

    def run():
        try:
            result = run_port_scan(target, port_range=port_range, callback=callback)
            if result.get("success"):
                vuln_result = assess_open_ports(result.get("open_ports", []))
                result["vulnerability_assessment"] = vuln_result
                result["findings"] = vuln_result.get("findings", [])
                result["total_findings"] = vuln_result.get("total_findings", 0)
                result["overall_risk"] = vuln_result.get("overall_risk", "LOW")
                result["scan_type"] = "Port Scan + Vulnerability Assessment"
                add_to_history("Port Scan", target, result)
            active_scans[scan_id]["status"] = "done"
            active_scans[scan_id]["result"] = result
            socketio.emit("scan_complete", {"scan_id": scan_id, "result": result})
        except Exception as e:
            active_scans[scan_id]["status"] = "error"
            socketio.emit("scan_error", {"scan_id": scan_id, "error": str(e)})

    t = threading.Thread(target=run)
    t.daemon = True
    t.start()

    return jsonify({"success": True, "scan_id": scan_id,
                    "message": f"Port scan started for {target}"})


# ─── API: Web Scanner ─────────────────────────────────────────────────────────

@app.route("/api/scan/web", methods=["POST"])
def api_web_scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"success": False, "error": "Target URL is required."}), 400

    scan_id = f"web_{int(time.time())}"
    active_scans[scan_id] = {"status": "running", "start": time.time()}

    def callback(event, payload):
        socketio.emit("scan_event", {"scan_id": scan_id, "event": event,
                                     "data": payload})

    def run():
        try:
            result = run_web_scan(target, callback=callback)
            result["scan_type"] = "Web Application Scan"
            add_to_history("Web Scan", target, result)
            active_scans[scan_id]["status"] = "done"
            active_scans[scan_id]["result"] = result
            socketio.emit("scan_complete", {"scan_id": scan_id, "result": result})
        except Exception as e:
            active_scans[scan_id]["status"] = "error"
            socketio.emit("scan_error", {"scan_id": scan_id, "error": str(e)})

    t = threading.Thread(target=run)
    t.daemon = True
    t.start()

    return jsonify({"success": True, "scan_id": scan_id,
                    "message": f"Web scan started for {target}"})


# ─── API: SSL Checker ─────────────────────────────────────────────────────────

@app.route("/api/scan/ssl", methods=["POST"])
def api_ssl_scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        port = int(data.get("port", 443))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Port must be a number between 1 and 65535."}), 400
    if not 1 <= port <= 65535:
        return jsonify({"success": False, "error": "Port must be between 1 and 65535."}), 400

    if not target:
        return jsonify({"success": False, "error": "Target hostname is required."}), 400

    scan_id = f"ssl_{int(time.time())}"

    def run():
        try:
            result = get_ssl_info(target, port)
            result["target"] = f"{target}:{port}"
            result["scan_type"] = "SSL/TLS Certificate Check"
            result["total_findings"] = len(result.get("findings", []))
            result["overall_risk"] = "LOW"
            sev = result.get("severity_count", {})
            if sev.get("CRITICAL", 0):
                result["overall_risk"] = "CRITICAL"
            elif sev.get("HIGH", 0):
                result["overall_risk"] = "HIGH"
            elif sev.get("MEDIUM", 0):
                result["overall_risk"] = "MEDIUM"
            add_to_history("SSL Check", target, result)
            active_scans[scan_id] = {"status": "done", "result": result}
            socketio.emit("scan_complete", {"scan_id": scan_id, "result": result})
        except Exception as e:
            active_scans[scan_id] = {"status": "error"}
            socketio.emit("scan_error", {"scan_id": scan_id, "error": str(e)})

    active_scans[scan_id] = {"status": "running", "start": time.time()}
    t = threading.Thread(target=run)
    t.daemon = True
    t.start()

    return jsonify({"success": True, "scan_id": scan_id,
                    "message": f"SSL check started for {target}:{port}"})


# ─── API: DNS Reconnaissance ──────────────────────────────────────────────────

@app.route("/api/scan/dns", methods=["POST"])
def api_dns_scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    enum_subs = data.get("enumerate_subdomains", True)

    if not target:
        return jsonify({"success": False, "error": "Target domain is required."}), 400

    scan_id = f"dns_{int(time.time())}"
    active_scans[scan_id] = {"status": "running", "start": time.time()}

    def callback(event, payload):
        socketio.emit("scan_event", {"scan_id": scan_id, "event": event,
                                     "data": payload})

    def run():
        try:
            result = run_dns_recon(target, enumerate_subdomains=enum_subs,
                                   callback=callback)
            result["scan_type"] = "DNS Reconnaissance"
            result["total_findings"] = len(result.get("findings", []))
            result["overall_risk"] = "LOW"
            sev = result.get("severity_count", {})
            if sev.get("HIGH", 0):
                result["overall_risk"] = "HIGH"
            elif sev.get("MEDIUM", 0):
                result["overall_risk"] = "MEDIUM"
            add_to_history("DNS Recon", target, result)
            active_scans[scan_id]["status"] = "done"
            active_scans[scan_id]["result"] = result
            socketio.emit("scan_complete", {"scan_id": scan_id, "result": result})
        except Exception as e:
            active_scans[scan_id]["status"] = "error"
            socketio.emit("scan_error", {"scan_id": scan_id, "error": str(e)})

    t = threading.Thread(target=run)
    t.daemon = True
    t.start()

    return jsonify({"success": True, "scan_id": scan_id,
                    "message": f"DNS recon started for {target}"})


# ─── API: Comprehensive Scan ──────────────────────────────────────────────────

@app.route("/api/scan/full", methods=["POST"])
def api_full_scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"success": False, "error": "Target is required."}), 400

    scan_id = f"full_{int(time.time())}"
    active_scans[scan_id] = {"status": "running", "start": time.time()}

    def callback(event, payload):
        socketio.emit("scan_event", {"scan_id": scan_id, "event": event,
                                     "data": payload})

    def run():
        combined = {
            "target": target,
            "scan_type": "Full Comprehensive VAPT",
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "findings": [],
            "severity_count": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        }

        # Port Scan
        callback("status", "Running port scan...")
        try:
            port_result = run_port_scan(target, port_range="common", callback=callback)
            if port_result.get("success"):
                combined["port_scan"] = port_result
                combined["ip"] = port_result.get("ip", "")
                vuln = assess_open_ports(port_result.get("open_ports", []))
                combined["findings"].extend(vuln.get("findings", []))
                for k, v in vuln.get("severity_count", {}).items():
                    combined["severity_count"][k] = combined["severity_count"].get(k, 0) + v
        except Exception as e:
            callback("status", f"Port scan error: {e}")

        # Web Scan
        callback("status", "Running web application scan...")
        try:
            web_url = target if target.startswith("http") else f"http://{target}"
            web_result = run_web_scan(web_url, callback=callback)
            if web_result.get("success"):
                combined["web_scan"] = web_result
                combined["findings"].extend(web_result.get("findings", []))
                for k, v in web_result.get("severity_count", {}).items():
                    combined["severity_count"][k] = combined["severity_count"].get(k, 0) + v
        except Exception as e:
            callback("status", f"Web scan error: {e}")

        # SSL Check
        callback("status", "Checking SSL/TLS certificate...")
        try:
            hostname = target.replace("https://", "").replace("http://", "").split("/")[0]
            ssl_result = get_ssl_info(hostname)
            if ssl_result.get("success"):
                combined["ssl_check"] = ssl_result
                combined["findings"].extend(ssl_result.get("findings", []))
                for k, v in ssl_result.get("severity_count", {}).items():
                    combined["severity_count"][k] = combined["severity_count"].get(k, 0) + v
        except Exception:
            pass

        # DNS Recon
        callback("status", "Running DNS reconnaissance...")
        try:
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            dns_result = run_dns_recon(domain, enumerate_subdomains=False)
            if dns_result.get("success"):
                combined["dns_recon"] = dns_result
                combined["findings"].extend(dns_result.get("findings", []))
                for k, v in dns_result.get("severity_count", {}).items():
                    combined["severity_count"][k] = combined["severity_count"].get(k, 0) + v
        except Exception:
            pass

        # Overall risk
        sc = combined["severity_count"]
        if sc.get("CRITICAL", 0):
            combined["overall_risk"] = "CRITICAL"
        elif sc.get("HIGH", 0):
            combined["overall_risk"] = "HIGH"
        elif sc.get("MEDIUM", 0):
            combined["overall_risk"] = "MEDIUM"
        else:
            combined["overall_risk"] = "LOW"

        combined["total_findings"] = len(combined["findings"])
        combined["findings"].sort(
            key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            .get(x.get("severity", "INFO"), 5)
        )
        add_to_history("Full VAPT", target, combined)
        active_scans[scan_id]["status"] = "done"
        active_scans[scan_id]["result"] = combined
        socketio.emit("scan_complete", {"scan_id": scan_id, "result": combined})

    t = threading.Thread(target=run)
    t.daemon = True
    t.start()

    return jsonify({"success": True, "scan_id": scan_id,
                    "message": f"Full VAPT scan started for {target}"})


# ─── API: Reports ─────────────────────────────────────────────────────────────

@app.route("/api/report/pdf", methods=["POST"])
def api_generate_pdf():
    data = request.get_json(silent=True) or {}
    scan_data = data.get("scan_data")
    if not scan_data:
        return jsonify({"success": False, "error": "No scan data provided."}), 400
    try:
        reports_dir = os.path.join(os.path.dirname(__file__), "reports")
        filepath = generate_pdf_report(scan_data, output_dir=reports_dir)
        return send_file(filepath, as_attachment=True,
                         download_name=os.path.basename(filepath),
                         mimetype="application/pdf")
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/report/json", methods=["POST"])
def api_generate_json():
    data = request.get_json(silent=True) or {}
    scan_data = data.get("scan_data")
    if not scan_data:
        return jsonify({"success": False, "error": "No scan data provided."}), 400
    try:
        reports_dir = os.path.join(os.path.dirname(__file__), "reports")
        filepath = generate_json_report(scan_data, output_dir=reports_dir)
        return send_file(filepath, as_attachment=True,
                         download_name=os.path.basename(filepath),
                         mimetype="application/json")
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/history")
def api_history():
    safe = []
    for entry in scan_history:
        safe.append({
            "id": entry["id"],
            "type": entry["type"],
            "target": entry["target"],
            "timestamp": entry["timestamp"],
            "overall_risk": entry["overall_risk"],
            "total_findings": entry["total_findings"],
        })
    return jsonify(safe)


@app.route("/api/history/<int:scan_id>")
def api_history_detail(scan_id):
    for entry in scan_history:
        if entry["id"] == scan_id:
            return jsonify(entry)
    return jsonify({"error": "Not found"}), 404


@app.route("/api/scan/status/<scan_id>")
def api_scan_status(scan_id):
    scan = active_scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({"scan_id": scan_id, "status": scan.get("status"),
                    "elapsed": round(time.time() - scan.get("start", time.time()), 1)})


# ─── SocketIO Events ──────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    emit("connected", {"message": "Connected to VAPT Scanner"})


@socketio.on("ping_server")
def on_ping():
    emit("pong", {"time": datetime.now().isoformat()})


def _pick_listen_port(preferred: int, listen_host: str) -> int:
    """If VAPT_PORT is not set, use the first free TCP port from *preferred* upward."""
    if os.environ.get("VAPT_PORT"):
        return preferred
    check_host = "127.0.0.1" if listen_host == "0.0.0.0" else listen_host
    for p in range(preferred, preferred + 30):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((check_host, p))
                return p
            except OSError:
                continue
    return preferred


if __name__ == "__main__":
    # Flask debug + Werkzeug + Socket.IO often hangs HTTP on Windows / Thonny (blank page, loading forever).
    # Enable only when needed:  set VAPT_DEBUG=1
    _debug = os.environ.get("VAPT_DEBUG", "").strip().lower() in ("1", "true", "yes")
    # Default 127.0.0.1: most reliable for "open in browser" on Windows; use VAPT_HOST=0.0.0.0 for LAN.
    _host = os.environ.get("VAPT_HOST", "127.0.0.1")
    _port = int(os.environ.get("VAPT_PORT", "5000"))
    _port = _pick_listen_port(_port, _host)
    _open_url = f"http://127.0.0.1:{_port}/"

    print("\n" + "="*60)
    print("  VAPT - Vulnerability Assessment & Penetration Testing")
    print("  Platform v1.0  |  Educational Use Only")
    print("="*60)
    print(f"  Open this URL:    {_open_url}")
    print(f"  Listening on:     {_host}:{_port}")
    print(f"  Flask debug:      {_debug}  (set VAPT_DEBUG=1 to enable)")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60 + "\n")

    _no_browser = os.environ.get("VAPT_NO_BROWSER", "").strip().lower() in ("1", "true", "yes")
    if not _no_browser:
        def _open_when_ready():
            time.sleep(1.25)
            print(f"  Opening browser: {_open_url}\n")
            webbrowser.open(_open_url)

        threading.Thread(target=_open_when_ready, daemon=True).start()

    # use_reloader=False: watchdog reloader breaks Socket.IO; restart app after code changes.
    socketio.run(
        app,
        debug=_debug,
        use_reloader=False,
        host=_host,
        port=_port,
        allow_unsafe_werkzeug=True,
    )
