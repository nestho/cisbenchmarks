#!/usr/bin/env python3
"""
tools/deep_cis_parser.py — High-Precision, Production-Grade CIS Benchmark PDF Parser

Extracts structured compliance controls from CIS Benchmark PDFs with deep section
state-machine tracking, multi-page script reconstruction, and companion YAML generation.
"""

import argparse
import glob
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pypdf
import yaml


# Common noise patterns in CIS PDFs
HEADER_FOOTER_PATTERNS = [
    re.compile(r'(?m)^Page\s+\d+\s*$'),
    re.compile(r'(?m)^Internal Only\s*-\s*General\s*$'),
    re.compile(r'(?m)^CIS\s+.*?Benchmark\s+v[\d\.]+\s*$'),
    re.compile(r'(?m)^©\s*Center for Internet Security\s*$'),
    re.compile(r'(?m)^This benchmark can be downloaded from.*?$'),
]

# Section anchor regexes
SECTION_HEADERS = [
    ("profile_applicability", re.compile(r'^(?:Profile\s+Applicability|Applicability)\s*:', re.IGNORECASE)),
    ("description", re.compile(r'^(?:Description)\s*:', re.IGNORECASE)),
    ("rationale", re.compile(r'^(?:Rationale)\s*:', re.IGNORECASE)),
    ("impact", re.compile(r'^(?:Impact)\s*:', re.IGNORECASE)),
    ("audit", re.compile(r'^(?:Audit)\s*:', re.IGNORECASE)),
    ("remediation", re.compile(r'^(?:Remediation)\s*:', re.IGNORECASE)),
    ("default_value", re.compile(r'^(?:Default\s+Value)\s*:', re.IGNORECASE)),
    ("references", re.compile(r'^(?:References)\s*:', re.IGNORECASE)),
    ("additional_info", re.compile(r'^(?:Additional\s+Information)\s*:', re.IGNORECASE)),
    ("cis_controls", re.compile(r'^(?:CIS\s+Controls)\s*:', re.IGNORECASE)),
]

RECOMMENDATION_START = re.compile(
    r'^(\d+(?:\.\d+){1,4})\s+(.*?)\s*\(((?:Automated|Manual|Scored|Not Scored|Automated\s*-\s*Scored|Manual\s*-\s*Not Scored|Automated\s*-\s*Not Scored))\)\s*$',
    re.IGNORECASE
)

TOC_DOTS = re.compile(r'\.{4,}\s*\d*$')


class DeepCISParser:
    def __init__(self, pdf_path: str):
        self.pdf_path = Path(pdf_path)
        self.reader = pypdf.PdfReader(str(self.pdf_path))
        self.total_pages = len(self.reader.pages)

    def clean_page(self, text: str) -> List[str]:
        """Strip running headers, page numbers, and normalize lines."""
        for pat in HEADER_FOOTER_PATTERNS:
            text = pat.sub('', text)
        
        # De-hyphenate broken words across line breaks e.g. "con- \n figuration"
        text = re.sub(r'(\w+)-\s*\n\s*(\w+)', r'\1\2', text)
        text = text.replace('\t', ' ')

        lines = [line.rstrip() for line in text.splitlines()]
        cleaned = []
        for l in lines:
            # normalize spacing if not leading indentation
            t = l.strip()
            if t:
                # normalize internal multiple spaces
                norm_line = re.sub(r' {2,}', ' ', l)
                cleaned.append(norm_line)
        return cleaned

    def extract_metadata(self) -> Dict[str, str]:
        """Extract benchmark Title, Version, Technology, and Platform from cover pages."""
        front_text = ""
        for p in range(min(5, self.total_pages)):
            front_text += (self.reader.pages[p].extract_text() or "") + "\n"

        title_m = re.search(r'(CIS\s+[\w\s\.-]+?Benchmark)', front_text, re.IGNORECASE)
        if title_m:
            title = re.sub(r'\s+', ' ', title_m.group(1)).strip()
        else:
            title = self.pdf_path.stem.replace('_', ' ')

        # Version
        ver_m = re.search(r'v(\d+\.\d+(?:\.\d+)?)', title + " " + self.pdf_path.name)
        version = ver_m.group(1) if ver_m else "1.0.0"

        # Technology / Category
        tech = self.pdf_path.parent.name
        category = self.pdf_path.parent.parent.name if self.pdf_path.parent.parent != self.pdf_path.parent else "General"

        bench_id = re.sub(r'[^a-z0-9]+', '-', title.lower()).strip('-')

        return {
            "id": bench_id,
            "title": title,
            "version": version,
            "technology": tech,
            "category": category,
            "file": self.pdf_path.name,
            "total_pages": self.total_pages,
        }

    def parse_controls(self, max_pages: Optional[int] = None) -> List[Dict[str, Any]]:
        limit = min(self.total_pages, max_pages) if max_pages else self.total_pages
        all_lines: List[Tuple[int, str]] = []

        for p_idx in range(limit):
            try:
                raw = self.reader.pages[p_idx].extract_text() or ""
                lines = self.clean_page(raw)
                for l in lines:
                    all_lines.append((p_idx + 1, l))
            except Exception:
                continue

        controls = []
        current_ctrl: Optional[Dict[str, Any]] = None
        current_section = "title"

        def finalize_control(ctrl: Optional[Dict[str, Any]]):
            if not ctrl:
                return
            # Post-process sections
            ctrl["description"] = " ".join(ctrl.get("description", [])).strip()
            ctrl["rationale"] = " ".join(ctrl.get("rationale", [])).strip()
            ctrl["impact"] = " ".join(ctrl.get("impact", [])).strip()
            audit_raw = "\n".join(ctrl.get("audit_lines", [])).strip()
            ctrl["audit_raw"] = audit_raw
            remed_raw = "\n".join(ctrl.get("remediation_lines", [])).strip()
            ctrl["remediation"] = remed_raw

            # Quality gate: discard false TOC or header matches with no content
            if not ctrl["description"] and not audit_raw and not remed_raw:
                return

            # Extract executable check from audit section
            checks = self.extract_checks(audit_raw, ctrl.get("title", ""))
            ctrl["checks"] = checks
            del ctrl["audit_lines"]
            del ctrl["remediation_lines"]
            controls.append(ctrl)

        i = 0
        while i < len(all_lines):
            page_no, line = all_lines[i]
            sline = line.strip()

            # Check if line starts a new recommendation e.g. "1.1.1.1 Ensure ... (Automated)"
            if TOC_DOTS.search(sline) or '....' in sline:
                i += 1
                continue

            # Handle possible 2-line title split
            candidate_line = sline
            if i + 1 < len(all_lines) and not sline.endswith(')'):
                next_line = all_lines[i + 1][1].strip()
                if '(' in next_line and next_line.endswith(')'):
                    candidate_line = sline + " " + next_line

            rec_match = RECOMMENDATION_START.match(candidate_line)
            if rec_match:
                finalize_control(current_ctrl)
                ctrl_id = rec_match.group(1)
                title = rec_match.group(2).strip()
                scoring_raw = rec_match.group(3).lower()
                scoring = "scored" if "automated" in scoring_raw or "scored" in scoring_raw else "manual"

                current_ctrl = {
                    "id": ctrl_id,
                    "title": title,
                    "scoring": scoring,
                    "profile": [],
                    "description": [],
                    "rationale": [],
                    "impact": [],
                    "audit_lines": [],
                    "remediation_lines": [],
                    "references": [],
                    "page_start": page_no,
                }
                current_section = "profile_applicability"
                if candidate_line != sline:
                    i += 1  # consumed 2 lines
                i += 1
                continue

            if current_ctrl is None:
                i += 1
                continue

            # Check section header transition
            matched_header = False
            for sec_name, sec_regex in SECTION_HEADERS:
                if sec_regex.match(sline):
                    current_section = sec_name
                    matched_header = True
                    break

            if matched_header:
                i += 1
                continue

            # Dispatch line to current section
            if current_section == "profile_applicability":
                if sline.startswith('•') or sline.startswith('-') or sline.startswith('*'):
                    prof = sline.lstrip('•-* ').strip()
                    if prof and prof not in current_ctrl["profile"]:
                        current_ctrl["profile"].append(prof)
                elif 'level 1' in sline.lower():
                    if 'level1' not in current_ctrl["profile"]:
                        current_ctrl["profile"].append("Level 1")
                elif 'level 2' in sline.lower():
                    if 'level2' not in current_ctrl["profile"]:
                        current_ctrl["profile"].append("Level 2")
            elif current_section == "description":
                current_ctrl["description"].append(sline)
            elif current_section == "rationale":
                current_ctrl["rationale"].append(sline)
            elif current_section == "impact":
                current_ctrl["impact"].append(sline)
            elif current_section == "audit":
                current_ctrl["audit_lines"].append(line)
            elif current_section == "remediation":
                current_ctrl["remediation_lines"].append(line)
            elif current_section == "references":
                if sline.startswith('http') or sline.startswith('1.') or sline.startswith('2.'):
                    current_ctrl["references"].append(sline)

            i += 1

        finalize_control(current_ctrl)
        return controls

    def extract_checks(self, audit_text: str, title: str) -> List[Dict[str, Any]]:
        """Deeply inspect audit text to construct executable commands, regexes, and checks."""
        checks = []
        trimmed = audit_text.strip()

        # 1. Check for complete multi-line Bash script in audit text
        if '#!/usr/bin/env bash' in trimmed or '#!/bin/sh' in trimmed or 'module_loadable_chk()' in trimmed:
            script_body = trimmed
            if '#!/usr/bin/' in script_body:
                script_body = script_body[script_body.find('#!/usr/bin/'):]
            checks.append({
                "type": "script",
                "interpreter": "bash",
                "script": script_body,
                "expected": "exit_0",
                "severity": "medium",
                "info": "CIS multi-line automated audit verification script."
            })
            return checks

        # 2. Check for PowerShell script / command
        if any(ps_indicator in trimmed for ps_indicator in [
            'Get-ItemProperty', 'Get-Service', 'auditpol /get', 'secedit /export', 'Get-Acl', 'HKLM:\\'
        ]):
            ps_lines = [l.strip() for l in trimmed.splitlines() if any(k in l for k in [
                'Get-ItemProperty', 'Get-Service', 'auditpol', 'secedit', 'Get-Acl', '$'
            ])]
            cmd = "\n".join(ps_lines) if ps_lines else trimmed[:300]
            checks.append({
                "type": "powershell",
                "command": cmd,
                "expected": "",
                "severity": "medium",
                "info": trimmed[:400]
            })
            return checks

        # 3. Check for Linux Shell Commands (grep, systemctl, sysctl, auditctl, etc.)
        cmd_candidates = []
        for line in trimmed.splitlines():
            s = line.strip()
            if any(s.startswith(p) for p in [
                'grep ', 'systemctl ', 'sysctl ', 'auditctl ', 'modprobe ', 'mount ',
                'find ', 'stat ', 'sshd ', 'ls ', 'cat ', 'chmod ', 'chown ', 'rpm ', 'dpkg ',
                'docker ', 'journalctl ', 'crontab '
            ]) or '| grep ' in s:
                cmd_candidates.append(s)

        if cmd_candidates:
            full_cmd = " && ".join(cmd_candidates)
            expected = ""
            # Look for expectations e.g. "should return...", "verify that..."
            for line in trimmed.splitlines():
                ll = line.lower()
                if 'should return' in ll or 'verify that' in ll or 'expected:' in ll:
                    expected = line.strip()
                    break

            checks.append({
                "type": "command",
                "command": full_cmd,
                "expected": expected,
                "severity": "medium",
                "info": trimmed[:400]
            })
            return checks

        # 4. Check for SQL Queries (SHOW ..., SELECT ...)
        if re.search(r'\b(SHOW\s+[a-zA-Z_]+|SELECT\s+.*?\s+FROM)\b', trimmed, re.IGNORECASE):
            sql_m = re.search(r'((?:SHOW|SELECT)\s+[^;\n]+;?)', trimmed, re.IGNORECASE)
            cmd = sql_m.group(1).strip() if sql_m else trimmed[:200]
            checks.append({
                "type": "sql",
                "command": cmd,
                "severity": "medium",
                "info": trimmed[:400]
            })
            return checks

        # Fallback to Manual Review
        checks.append({
            "type": "manual_review",
            "info": trimmed[:500] or "Manual audit procedure required by CIS standard.",
            "severity": "medium"
        })
        return checks


def parse_and_save(pdf_path: Path, output_path: Optional[Path] = None, max_pages: Optional[int] = None) -> Path:
    parser = DeepCISParser(str(pdf_path))
    meta = parser.extract_metadata()
    controls = parser.parse_controls(max_pages=max_pages)

    doc = {
        "benchmark": {
            "id": meta["id"],
            "title": meta["title"],
            "version": meta["version"],
            "technology": meta["technology"],
            "category": meta["category"],
            "os": meta["technology"],
            "source_pdf": meta["file"],
            "total_pages": meta["total_pages"],
            "controls_count": len(controls),
        },
        "controls": controls,
    }

    if output_path is None:
        # Put beside its own CIS PDF!
        output_path = pdf_path.with_suffix(".yaml")

    yaml_str = yaml.dump(doc, sort_keys=False, width=120, allow_unicode=True)
    output_path.write_text(yaml_str, encoding="utf-8")
    return output_path


def main():
    p = argparse.ArgumentParser(description="Deep High-Precision CIS Benchmark PDF Parser")
    p.add_argument("target", help="Path to a CIS PDF file or directory of PDFs")
    p.add_argument("-o", "--output", help="Explicit output file or directory (default: beside PDF)")
    p.add_argument("--pages", type=int, default=None, help="Max pages per PDF (for testing)")
    p.add_argument("--batch", action="store_true", help="Process all PDFs in target directory recursively")
    args = p.parse_args()

    target_path = Path(args.target)
    if not target_path.exists():
        print(f"Error: path not found: {target_path}", file=sys.stderr)
        sys.exit(1)

    if target_path.is_file() and not args.batch:
        out = Path(args.output) if args.output else None
        print(f"[*] Deep parsing CIS PDF: {target_path.name}")
        saved = parse_and_save(target_path, out, max_pages=args.pages)
        print(f"[+] Saved companion canonical YAML: {saved}")
    else:
        # Batch mode: find all PDFs
        pattern = str(target_path / "**" / "*.pdf")
        pdf_list = [Path(p) for p in glob.glob(pattern, recursive=True)]
        print(f"[*] Found {len(pdf_list)} CIS PDFs in {target_path}")

        count = 0
        for pdf in pdf_list:
            try:
                saved = parse_and_save(pdf, max_pages=args.pages)
                count += 1
                print(f"[{count}/{len(pdf_list)}] -> {saved.name}")
            except Exception as e:
                print(f"[!] Error on {pdf.name}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
