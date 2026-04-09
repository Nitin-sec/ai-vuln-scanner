"""
ThreatMap Enterprise Report Generator (VAPT Standard - FINAL)
"""

import openpyxl
from openpyxl.styles import PatternFill, Font
from datetime import datetime


SEVERITY_COLORS = {
    "Critical": "FF4C4C",
    "High": "FF8C00",
    "Medium": "FFA500",
    "Low": "FFD700",
    "Info": "4DA6FF"
}


def generate_excel(db, output_path="reports/threatmap_report.xlsx"):
    records = db.get_all_triage()

    if not records:
        print("[!] No findings.")
        return None

    wb = openpyxl.Workbook()

    # =========================
    # SHEET 1 — EXEC SUMMARY
    # =========================
    ws1 = wb.active
    ws1.title = "Executive Summary"

    severities = ["Critical", "High", "Medium", "Low", "Info"]
    counts = {s: 0 for s in severities}

    for r in records:
        if r["severity"] in counts:
            counts[r["severity"]] += 1

    ws1["A1"] = "ThreatMap Infra — VAPT Report"
    ws1["A3"] = "Target"
    ws1["B3"] = records[0]["host"]

    ws1["A4"] = "Date"
    ws1["B4"] = datetime.now().strftime("%Y-%m-%d")

    ws1["A6"] = "Risk Summary"

    row = 7
    for sev in severities:
        ws1.cell(row=row, column=1, value=sev)
        cell = ws1.cell(row=row, column=2, value=counts[sev])
        cell.fill = PatternFill(start_color=SEVERITY_COLORS[sev],
                                end_color=SEVERITY_COLORS[sev],
                                fill_type="solid")
        row += 1

    # =========================
    # SHEET 2 — FINDINGS TABLE
    # =========================
    ws2 = wb.create_sheet("Findings")

    headers = ["ID", "Title", "Severity", "Host"]

    for col, h in enumerate(headers, 1):
        cell = ws2.cell(row=1, column=col, value=h)
        cell.fill = PatternFill(start_color="1A1A2E", fill_type="solid")
        cell.font = Font(color="FFFFFF", bold=True)

    for i, r in enumerate(records, 2):
        ws2.cell(row=i, column=1, value=f"VULN-{i-1:03}")
        ws2.cell(row=i, column=2, value=f"Exposed {r['service'].upper()} Service")
        ws2.cell(row=i, column=3, value=r["severity"])
        ws2.cell(row=i, column=4, value=r["host"])

    # =========================
    # SHEET 3 — DETAILED FINDINGS
    # =========================
    ws3 = wb.create_sheet("Detailed Findings")

    headers = [
        "ID", "Title", "Severity", "CVSS",
        "Host", "Port", "Service",
        "Description", "Impact",
        "Recommendation"
    ]

    for col, h in enumerate(headers, 1):
        cell = ws3.cell(row=1, column=col, value=h)
        cell.fill = PatternFill(start_color="1A1A2E", fill_type="solid")
        cell.font = Font(color="FFFFFF", bold=True)

    for i, r in enumerate(records, 2):
        ws3.cell(row=i, column=1, value=f"VULN-{i-1:03}")
        ws3.cell(row=i, column=2, value=f"Exposed {r['service'].upper()} Service")
        ws3.cell(row=i, column=3, value=r["severity"])
        ws3.cell(row=i, column=4, value=r["cvss_score"])
        ws3.cell(row=i, column=5, value=r["host"])
        ws3.cell(row=i, column=6, value=r["port"])
        ws3.cell(row=i, column=7, value=r["service"])

        ws3.cell(row=i, column=8, value=r["risk_summary"])
        ws3.cell(row=i, column=9, value=r["business_impact"])
        ws3.cell(row=i, column=10, value=r["remediation"])

    wb.save(output_path)

    print(f"[✔] Enterprise VAPT report generated → {output_path}")
    return output_path
