#!/usr/bin/env python3
"""
tools/generate_egk_report.py — HardenX Master EGK 15-Sheet Excel Workbook Generator

Generates the regulatory-compliant 15-sheet Excel workbook based on official EGK standard:
- Dual Assessment: CIS Compliance (Online/Offline) & Vulnerability Assessment (CSAF VEX / OVAL / KEV)
- 3-Party Regulatory Review Columns: Auditor Status/Comment, Owner Status/Comment, Auditor Status2/Comment2
- Bilingual Typography: Persian Right-to-Left (RTL) vs English Left-to-Right (LTR)
- Static ISO Dates (no volatile Excel formulas)
"""

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import openpyxl
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

# Formatting palettes
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_FILL = {
    "Critical": PatternFill("solid", fgColor="9C0006"),
    "High": PatternFill("solid", fgColor="ED7D31"),
    "Medium": PatternFill("solid", fgColor="FFC000"),
    "Low": PatternFill("solid", fgColor="70AD47"),
    "Info": PatternFill("solid", fgColor="5B9BD5"),
}
SEVERITY_FONT = {
    "Critical": Font(name="Calibri", size=11, bold=True, color="FFFFFF"),
    "High": Font(name="Calibri", size=11, bold=True, color="FFFFFF"),
    "Medium": Font(name="Calibri", size=11, bold=True, color="000000"),
    "Low": Font(name="Calibri", size=11, bold=True, color="FFFFFF"),
    "Info": Font(name="Calibri", size=11, bold=True, color="FFFFFF"),
}

STATUS_FILL = {
    "Done": PatternFill("solid", fgColor="E2EFDA"),    # soft green
    "Undone": PatternFill("solid", fgColor="FCE4D6"),  # soft red
    "N/A": PatternFill("solid", fgColor="EDEDED"),     # soft gray
    "Missing Evidence": PatternFill("solid", fgColor="FFF2CC"), # soft yellow
}
STATUS_FONT = {
    "Done": Font(name="Calibri", size=10, bold=True, color="375623"),
    "Undone": Font(name="Calibri", size=10, bold=True, color="C65911"),
    "N/A": Font(name="Calibri", size=10, color="595959"),
    "Missing Evidence": Font(name="Calibri", size=10, color="806000"),
}

THIN = Side(style="thin", color="B4B4B4")
THIN_BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
CENTER = Alignment(horizontal="center", vertical="center", wrap_text=True)
LEFT = Alignment(horizontal="left", vertical="center", wrap_text=True)
RIGHT = Alignment(horizontal="right", vertical="center", wrap_text=True)

_PERSIAN_RE = re.compile(r"[\u0600-\u06FF]")

def is_persian(text: Any) -> bool:
    return bool(_PERSIAN_RE.search(str(text or "")))

def align_for(text: Any, center: bool = False) -> Alignment:
    if center:
        return CENTER
    if is_persian(text):
        return RIGHT
    return LEFT

def set_cell(ws, row: int, col: int, val: Any, fill=None, font=None, center: bool = False):
    cell = ws.cell(row, col)
    if type(cell).__name__ == "MergedCell":
        for m in ws.merged_cells.ranges:
            if m.min_row <= row <= m.max_row and m.min_col <= col <= m.max_col:
                cell = ws.cell(m.min_row, m.min_col)
                break
    cell.value = val
    cell.border = THIN_BORDER
    cell.alignment = align_for(val, center=center)
    if fill:
        cell.fill = fill
    if font:
        cell.font = font

def main():
    parser = argparse.ArgumentParser(description="Generate official 15-Sheet EGK Excel Workbook")
    parser.add_argument("--job-json", help="Path to HardenX scan job JSON")
    parser.add_argument("--benchmark-json", help="Path to Benchmark JSON / YAML")
    parser.add_argument("--evidence-file", help="Path to raw evidence .txt file (Offline VA)")
    parser.add_argument("--template", help="Path to assessment_template.xlsx",
                        default="/Users/nestho/hardenx/platform/engine/ova/assessment_template.xlsx")
    parser.add_argument("--output", required=True, help="Destination .xlsx path")
    args = parser.parse_args()

    template_path = Path(args.template)
    if not template_path.exists():
        print(f"[-] Error: template not found at {template_path}", file=sys.stderr)
        sys.exit(1)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    job_data = {}
    if args.job_json and Path(args.job_json).exists():
        job_data = json.loads(Path(args.job_json).read_text(encoding="utf-8"))

    bm_data = {}
    if args.benchmark_json and Path(args.benchmark_json).exists():
        bm_data = json.loads(Path(args.benchmark_json).read_text(encoding="utf-8"))

    evidence_text = ""
    if args.evidence_file and Path(args.evidence_file).exists():
        evidence_text = Path(args.evidence_file).read_text(encoding="utf-8", errors="replace")

    # Load workbook template
    wb = openpyxl.load_workbook(str(template_path))

    asset = job_data.get("asset", {})
    host = asset.get("host") or asset.get("hostname") or "target-node"
    ip = asset.get("ip") or asset.get("host") or "10.0.0.1"
    created_at = job_data.get("created_at", "2026-10-27T12:00:00Z")[:10]

    # 1. Sheet: Cover
    if "Cover" in wb.sheetnames:
        ws = wb["Cover"]
        # Find cells for System Name / IP Address
        for r in range(1, 30):
            for c in range(1, 10):
                val = str(ws.cell(r, c).value or "")
                if "System Name" in val or "نام سامانه" in val:
                    set_cell(ws, r, c + 1, host)
                elif "IP Address" in val or "آدرس" in val:
                    set_cell(ws, r, c + 1, ip)
                elif "Date" in val or "تاریخ" in val:
                    set_cell(ws, r, c + 1, created_at)

    # 2. Sheet: Host information
    if "Host information" in wb.sheetnames:
        ws = wb["Host information"]
        os_name = asset.get("os", "Linux")
        set_cell(ws, 4, 2, host)
        set_cell(ws, 5, 2, ip)
        set_cell(ws, 6, 2, os_name)
        set_cell(ws, 7, 2, asset.get("protocol", "SSH"))

    # 3. Sheet: Compliance
    if "Compliance" in wb.sheetnames:
        ws = wb["Compliance"]
        results = job_data.get("results", [])
        controls_by_id = {c.get("id"): c for c in bm_data.get("controls", [])}

        # Clear existing rows from 18 downward
        start_row = 18
        max_r = max(ws.max_row, 30)
        for r in range(start_row, max_r + 1):
            for c in range(1, 16):
                cell = ws.cell(r, c)
                cell.value = None
                cell.fill = PatternFill(fill_type=None)

        done_count = 0
        undone_count = 0
        na_count = 0
        missing_count = 0

        curr_row = start_row
        for idx, res in enumerate(results, 1):
            cid = res.get("control_id", f"1.{idx}")
            ctrl = controls_by_id.get(cid, {})
            title = ctrl.get("title") or res.get("control_title") or f"CIS Control {cid}"
            desc = ctrl.get("description", "")
            rationale = ctrl.get("rationale", "")
            fix = ctrl.get("remediation", "")
            evidence = res.get("evidence", "")
            status = res.get("status", "pass")

            if status == "pass":
                egk_status = "Done"
                done_count += 1
                auditor_comment = "Compliant with CIS benchmark baseline."
            elif status == "fail":
                egk_status = "Undone"
                undone_count += 1
                auditor_comment = "Finding verified. Apply recommended remediation playbook."
            elif status == "error":
                egk_status = "Missing Evidence"
                missing_count += 1
                auditor_comment = f"Execution error: {res.get('error', 'command failed')}"
            else:
                egk_status = "N/A"
                na_count += 1
                auditor_comment = "Control not applicable to current asset profile."

            fill = STATUS_FILL.get(egk_status)
            font = STATUS_FONT.get(egk_status)

            # Columns in Row 17:
            # 1: No.
            # 2: Title|Name Testcase
            # 3: Info|Description
            # 4: Check
            # 5: Fix|Solution
            # 6: Policy Value
            # 7: Result (Command Evidence)
            # 8: Auditor's Status
            # 9: Auditor's Comment
            # 10: Owner's Status
            # 11: Owner's Comment
            # 12: Auditor's Status2
            # 13: Auditor's Comment2
            # 14: Owner's Status2
            # 15: Owner's Comment2
            check_cmd = res.get("check_type", "command")
            set_cell(ws, curr_row, 1, idx, center=True)
            set_cell(ws, curr_row, 2, f"{cid} {title}")
            set_cell(ws, curr_row, 3, desc or rationale)
            set_cell(ws, curr_row, 4, f"Check Type: {check_cmd}")
            set_cell(ws, curr_row, 5, fix)
            set_cell(ws, curr_row, 6, "CIS Benchmark Enforcement")
            set_cell(ws, curr_row, 7, evidence[:1000] if evidence else "Evaluated by HardenX Engine")
            set_cell(ws, curr_row, 8, egk_status, fill=fill, font=font, center=True)
            set_cell(ws, curr_row, 9, auditor_comment)
            set_cell(ws, curr_row, 10, "")
            set_cell(ws, curr_row, 11, "")
            set_cell(ws, curr_row, 12, "")
            set_cell(ws, curr_row, 13, "")
            set_cell(ws, curr_row, 14, "")
            set_cell(ws, curr_row, 15, "")

            curr_row += 1

        # Summary KPIs in row 9 if available
        set_cell(ws, 9, 1, len(results), center=True)
        set_cell(ws, 9, 2, done_count, center=True)
        set_cell(ws, 9, 3, undone_count, center=True)
        set_cell(ws, 9, 4, na_count, center=True)
        set_cell(ws, 9, 5, missing_count, center=True)

    # 4. Sheet: Summary
    if "Summary" in wb.sheetnames:
        ws = wb["Summary"]
        for r in range(1, 30):
            label = str(ws.cell(r, 1).value or "").strip()
            if "Total Checks" in label or "کل آزمون" in label:
                set_cell(ws, r, 2, len(job_data.get("results", [])), center=True)
            elif "Compliant" in label or "منطبق" in label:
                set_cell(ws, r, 2, done_count, center=True)
            elif "Non-Compliant" in label or "نامنطبق" in label:
                set_cell(ws, r, 2, undone_count, center=True)

    # 5. Sheet: Vulnerabilities (VA & Layer 8 findings)
    va_data = job_data.get("va_results") or {}
    vuln_data = va_data.get("vulnerabilities") or {}
    vulns = vuln_data.get("vulnerabilities") or []
    l8_data = job_data.get("layer8") or {}
    l8_findings = l8_data.get("findings") or []

    if "Vulnerabilities" in wb.sheetnames and (vulns or l8_findings):
        ws = wb["Vulnerabilities"]
        # Clear existing sample data from row 2 downward
        for r in range(2, max(ws.max_row, 30) + 1):
            for c in range(1, 12):
                set_cell(ws, r, c, None)

        v_row = 2
        # Write Layer 8 Anomalies first
        for finding in l8_findings:
            sev = finding.get("severity", "HIGH").capitalize()
            set_cell(ws, v_row, 1, v_row - 1, center=True)
            set_cell(ws, v_row, 2, finding.get("id", "L8-ANOMALY"))
            set_cell(ws, v_row, 3, sev)
            set_cell(ws, v_row, 4, finding.get("rule_name", "In-Memory Compromise Indicator"))
            set_cell(ws, v_row, 5, f"{finding.get('description', '')}\n[Evidence]: {finding.get('evidence', '')}")
            set_cell(ws, v_row, 6, finding.get("remediation", "Forensic analysis and containment"))
            set_cell(ws, v_row, 7, finding.get("category", "Layer 8 Memory"))
            set_cell(ws, v_row, 8, "RAM Active")
            set_cell(ws, v_row, 9, "N/A (Memory Threat)")
            set_cell(ws, v_row, 10, "Immediate Remediation Required")
            set_cell(ws, v_row, 11, finding.get("target", "Memory"))
            v_row += 1

        # Write Evaluated CVEs
        for v in vulns:
            sev = v.get("severity", "MEDIUM").capitalize()
            cve = v.get("cve_id", "CVE-UNKNOWN")
            if v.get("is_kev"):
                cve += " [CISA KEV EXPLOITED]"
            set_cell(ws, v_row, 1, v_row - 1, center=True)
            set_cell(ws, v_row, 2, cve)
            set_cell(ws, v_row, 3, sev)
            set_cell(ws, v_row, 4, v.get("title", "Package Vulnerability"))
            desc = f"Vulnerability detected in {v.get('package_name', '')} version {v.get('installed_version', '')}."
            if v.get("is_kev"):
                desc += " Active in-the-wild exploitation confirmed by CISA KEV."
            set_cell(ws, v_row, 5, desc)
            set_cell(ws, v_row, 6, v.get("remediation", "Upgrade package"))
            set_cell(ws, v_row, 7, v.get("package_name", "Package"))
            set_cell(ws, v_row, 8, v.get("installed_version", ""))
            set_cell(ws, v_row, 9, v.get("fixed_version", ""))
            set_cell(ws, v_row, 10, "OS Security Update")
            set_cell(ws, v_row, 11, "/usr/bin / system")
            v_row += 1

    # 6. Sheet: Package (Installed Package Ledger)
    host_ledger = va_data.get("host_ledger") or {}
    pkgs = host_ledger.get("packages") or []
    if "Package" in wb.sheetnames and pkgs:
        ws = wb["Package"]
        for r in range(2, max(ws.max_row, 30) + 1):
            for c in range(1, 6):
                set_cell(ws, r, c, None)
        p_row = 2
        for p in pkgs[:500]:
            set_cell(ws, p_row, 1, p_row - 1, center=True)
            set_cell(ws, p_row, 2, p.get("name", ""))
            set_cell(ws, p_row, 3, p.get("version", ""))
            set_cell(ws, p_row, 4, p.get("release", p.get("architecture", "")))
            set_cell(ws, p_row, 5, p.get("vendor", "Vendor Official"))
            p_row += 1

    # Save to atomic temp file and replace
    fd, temp_path = tempfile.mkstemp(prefix=".egk-wb-", suffix=".xlsx", dir=str(output_path.parent))
    os.close(fd)
    try:
        wb.save(temp_path)
        os.replace(temp_path, output_path)
        print(f"[+] Successfully generated official EGK 15-Sheet Workbook: {output_path} ({output_path.stat().st_size:,} bytes)")
    finally:
        Path(temp_path).unlink(missing_ok=True)

if __name__ == "__main__":
    main()
