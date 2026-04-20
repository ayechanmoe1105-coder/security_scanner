"""
PDF & JSON Report Generator Module
"""
import json
import os
from datetime import datetime
from fpdf import FPDF
from fpdf.enums import XPos, YPos


SEVERITY_COLORS = {
    "CRITICAL": (220, 38, 38),
    "HIGH": (234, 88, 12),
    "MEDIUM": (202, 138, 4),
    "LOW": (22, 163, 74),
    "INFO": (59, 130, 246),
}

RISK_BG = {
    "CRITICAL": (254, 226, 226),
    "HIGH": (255, 237, 213),
    "MEDIUM": (254, 249, 195),
    "LOW": (220, 252, 231),
    "INFO": (219, 234, 254),
}


class VAPTReport(FPDF):
    def __init__(self, title="VAPT Security Assessment Report"):
        super().__init__()
        self.report_title = title
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        self.set_fill_color(15, 23, 42)
        self.rect(0, 0, 210, 20, "F")
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(255, 255, 255)
        self.set_y(5)
        self.cell(0, 10, self.report_title, align="C")
        self.set_text_color(0, 0, 0)
        self.ln(14)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10,
                  f"VAPT Security Report  |  Page {self.page_no()}  |  Generated {datetime.now().strftime('%Y-%m-%d')}",
                  align="C")

    def section_title(self, text: str):
        self.set_font("Helvetica", "B", 12)
        self.set_fill_color(30, 41, 59)
        self.set_text_color(255, 255, 255)
        self.cell(0, 9, f"  {text}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        self.set_text_color(0, 0, 0)
        self.ln(3)

    def key_value(self, key: str, value: str):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(71, 85, 105)
        self.cell(45, 6, key + ":", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(15, 23, 42)
        self.multi_cell(0, 6, str(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def severity_badge(self, severity: str, x=None, y=None):
        color = SEVERITY_COLORS.get(severity, (100, 100, 100))
        if x:
            self.set_x(x)
        self.set_font("Helvetica", "B", 8)
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.cell(22, 6, severity, fill=True, align="C",
                  new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_text_color(0, 0, 0)

    def finding_card(self, finding: dict, index: int):
        severity = finding.get("severity", "INFO")
        bg = RISK_BG.get(severity, (245, 245, 245))
        border_color = SEVERITY_COLORS.get(severity, (100, 100, 100))

        self.set_fill_color(*bg)
        self.set_draw_color(*border_color)
        start_y = self.get_y()
        self.rect(self.l_margin, start_y, 180, 4, "F")

        self.set_fill_color(*border_color)
        self.rect(self.l_margin, start_y, 3, 4, "F")

        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*border_color)
        self.set_x(self.l_margin + 5)
        title = f"[{index}] {finding.get('type', 'Finding')}"
        self.cell(130, 4, title[:70], new_x=XPos.RIGHT, new_y=YPos.TOP)

        self.severity_badge(severity)
        cve = finding.get("cve", "")
        if cve:
            self.set_font("Helvetica", "", 7)
            self.set_text_color(100, 100, 100)
            self.cell(0, 4, f"  {cve}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            self.ln(4)

        self.set_fill_color(*bg)
        body_start = self.get_y()

        for label, key in [("Description", "description"), ("Detail", "detail"),
                            ("Evidence", "evidence"), ("Remediation", "remediation")]:
            val = finding.get(key, "")
            if val:
                self.set_x(self.l_margin + 5)
                self.set_font("Helvetica", "B", 8)
                self.set_text_color(71, 85, 105)
                self.cell(28, 5, label + ":", new_x=XPos.RIGHT, new_y=YPos.TOP)
                self.set_font("Helvetica", "", 8)
                self.set_text_color(30, 30, 30)
                self.multi_cell(147, 5, str(val)[:300],
                                new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        body_end = self.get_y()
        height = body_end - body_start + 2
        self.rect(self.l_margin, body_start, 180, height, "F")
        self.rect(self.l_margin, body_start, 3, height, "F")
        self.set_draw_color(0, 0, 0)
        self.ln(3)

    def risk_summary_table(self, severity_count: dict):
        self.set_font("Helvetica", "B", 9)
        headers = ["Severity", "Count", "Risk Level"]
        widths = [50, 30, 100]
        self.set_fill_color(30, 41, 59)
        self.set_text_color(255, 255, 255)
        for h, w in zip(headers, widths):
            self.cell(w, 7, h, border=1, fill=True, align="C")
        self.ln()

        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        risk_labels = {
            "CRITICAL": "Immediate action required",
            "HIGH": "Address as soon as possible",
            "MEDIUM": "Address in near term",
            "LOW": "Address when convenient",
            "INFO": "Informational only",
        }
        self.set_font("Helvetica", "", 9)
        for sev in order:
            count = severity_count.get(sev, 0)
            color = SEVERITY_COLORS.get(sev, (100, 100, 100))
            self.set_fill_color(*color)
            self.set_text_color(255, 255, 255)
            self.cell(widths[0], 6, sev, border=1, fill=True, align="C")
            self.set_fill_color(248, 248, 248)
            self.set_text_color(0, 0, 0)
            self.cell(widths[1], 6, str(count), border=1, fill=True, align="C")
            self.cell(widths[2], 6, risk_labels[sev], border=1, fill=True)
            self.ln()
        self.ln(4)


def generate_pdf_report(scan_data: dict, output_dir: str = "reports") -> str:
    """Generate a comprehensive PDF report from scan data."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = scan_data.get("target", "unknown").replace("://", "_").replace("/", "_").replace(":", "_")
    filename = f"vapt_report_{target}_{timestamp}.pdf"
    filepath = os.path.join(output_dir, filename)

    pdf = VAPTReport()
    pdf.add_page()

    # Cover / Summary
    pdf.section_title("Executive Summary")
    pdf.key_value("Target", scan_data.get("target", "N/A"))
    pdf.key_value("IP Address", scan_data.get("ip", scan_data.get("domain", "N/A")))
    pdf.key_value("Scan Date", scan_data.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    pdf.key_value("Scan Type", scan_data.get("scan_type", "Comprehensive VAPT"))
    pdf.key_value("Overall Risk", scan_data.get("overall_risk", "N/A"))
    pdf.key_value("Total Findings", str(scan_data.get("total_findings", 0)))
    pdf.ln(4)

    # Risk Summary Table
    severity_count = scan_data.get("severity_count", {})
    if severity_count:
        pdf.section_title("Risk Summary")
        pdf.risk_summary_table(severity_count)

    # Open Ports (if port scan)
    open_ports = scan_data.get("open_ports", [])
    if open_ports:
        pdf.section_title(f"Open Ports ({len(open_ports)} found)")
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(30, 41, 59)
        pdf.set_text_color(255, 255, 255)
        for h, w in zip(["Port", "Service", "Risk", "Description"], [25, 40, 25, 90]):
            pdf.cell(w, 7, h, border=1, fill=True, align="C")
        pdf.ln()
        pdf.set_font("Helvetica", "", 8)
        for p in open_ports:
            color = SEVERITY_COLORS.get(p.get("risk", "INFO"), (100, 100, 100))
            pdf.set_fill_color(248, 248, 248)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(25, 6, str(p.get("port", "")), border=1, fill=True, align="C")
            pdf.cell(40, 6, p.get("service", "")[:20], border=1, fill=True)
            pdf.set_fill_color(*color)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(25, 6, p.get("risk", "INFO"), border=1, fill=True, align="C")
            pdf.set_fill_color(248, 248, 248)
            pdf.set_text_color(0, 0, 0)
            desc = p.get("description", "")[:60]
            pdf.cell(90, 6, desc, border=1, fill=True)
            pdf.ln()
        pdf.ln(4)

    # Vulnerability Findings
    all_findings = scan_data.get("findings", [])
    if all_findings:
        pdf.section_title(f"Vulnerability Findings ({len(all_findings)} total)")
        for i, finding in enumerate(all_findings, 1):
            if pdf.get_y() > 240:
                pdf.add_page()
            pdf.finding_card(finding, i)

    # DNS Records
    dns_records = scan_data.get("dns_records", {})
    if dns_records:
        pdf.add_page()
        pdf.section_title("DNS Records")
        for rtype, values in dns_records.items():
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(20, 6, rtype, border=1, fill=False, align="C")
            pdf.set_font("Helvetica", "", 9)
            pdf.multi_cell(0, 6, ", ".join(values[:5]))

    # SSL Info
    cert_info = scan_data.get("certificate", {})
    if cert_info:
        if pdf.get_y() > 200:
            pdf.add_page()
        pdf.section_title("SSL/TLS Certificate Details")
        for k, v in cert_info.items():
            if isinstance(v, list):
                v = ", ".join(v[:5])
            pdf.key_value(k.replace("_", " ").title(), str(v))

    pdf.output(filepath)
    return filepath


def generate_json_report(scan_data: dict, output_dir: str = "reports") -> str:
    """Save scan data as a JSON report."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = scan_data.get("target", "unknown").replace("://", "_").replace("/", "_").replace(":", "_")
    filename = f"vapt_report_{target}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, indent=2, default=str)
    return filepath
