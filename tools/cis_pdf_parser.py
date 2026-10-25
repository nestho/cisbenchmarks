#!/usr/bin/env python3
"""
tools/cis_pdf_parser.py — Parse CIS Benchmark PDFs into Canonical YAML/JSON Audits.

Compatible with the HardenX / OpenCompliance format.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
import pypdf
import yaml


def clean_text(text: str) -> str:
    # remove footer/header noise like "Page 19 \nInternal Only - General"
    text = re.sub(r'Page\s+\d+\s*\nInternal Only - General\s*\n?', '', text)
    text = re.sub(r'Internal Only - General\s*\n?', '', text)
    return text


def extract_audit_command(audit_text: str) -> Dict[str, str]:
    """Extract candidate command and expectation from CIS Audit section text."""
    lines = [line.strip() for line in audit_text.splitlines() if line.strip()]
    cmds = []
    expected = ""
    for line in lines:
        # common shell indicators or execution verbs in CIS audit text
        if any(line.startswith(prefix) for prefix in [
            'grep ', 'mount ', 'systemctl ', 'modprobe ', 'auditctl ', 'sysctl ',
            'docker ', 'sshd ', 'cat ', 'ls ', 'stat ', 'find ', 'chmod ', 'chown ',
            'Get-ItemProperty', 'Get-Service', 'auditpol', 'secedit', 'rpm -q', 'dpkg -s'
        ]) or re.search(r'\b(grep|awk|sed|systemctl|sysctl|auditctl|docker)\b', line):
            cmds.append(line)
        elif 'should return' in line.lower() or 'verify' in line.lower() or 'expected' in line.lower():
            if not expected:
                expected = line

    cmd = " && ".join(cmds) if cmds else (lines[0] if lines else "")
    return {
        "command": cmd,
        "expected": expected
    }


def parse_cis_pdf(pdf_path: str, max_pages: Optional[int] = None) -> Dict[str, Any]:
    reader = pypdf.PdfReader(pdf_path)
    total_pages = len(reader.pages)
    limit = min(total_pages, max_pages) if max_pages else total_pages

    full_text = []
    for i in range(limit):
        try:
            page_text = reader.pages[i].extract_text() or ""
            full_text.append(clean_text(page_text))
        except Exception as e:
            continue

    corpus = "\n".join(full_text)

    # Extract title and version from first 5 pages
    front_matter = "\n".join(full_text[:min(5, len(full_text))])
    title_match = re.search(r'(CIS\s+[\w\s\.-]+Benchmark)', front_matter, re.IGNORECASE)
    title = title_match.group(1).strip() if title_match else Path(pdf_path).stem.replace('_', ' ')
    
    version_match = re.search(r'v(\d+\.\d+(\.\d+)?)', title + " " + Path(pdf_path).name)
    version = version_match.group(1) if version_match else "1.0.0"

    bench_id = re.sub(r'[^a-zA-Z0-9]+', '-', title.lower()).strip('-')

    # Regex to split on numbered recommendations, e.g. "1.1.1 Ensure ..."
    rec_pattern = re.compile(
        r'(?m)^(\d+(?:\.\d+){2,4})\s+([^\n]+?\((?:Automated|Manual)\))\s*\n'
    )

    matches = list(rec_pattern.finditer(corpus))
    controls = []

    for idx, match in enumerate(matches):
        ctrl_id = match.group(1)
        header = match.group(2).strip()

        scoring = "manual"
        if "(Automated)" in header:
            scoring = "scored"
            title_text = header.replace("(Automated)", "").strip()
        elif "(Manual)" in header:
            scoring = "manual"
            title_text = header.replace("(Manual)", "").strip()
        else:
            title_text = header

        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(corpus)
        block = corpus[start:end]

        # Extract sections
        def get_section(name: str, next_names: List[str]) -> str:
            next_pat = "|".join([re.escape(n) for n in next_names])
            pat = rf'{name}:\s*\n(.*?)(?=\n(?:{next_pat}):|\Z)'
            m = re.search(pat, block, re.DOTALL | re.IGNORECASE)
            return m.group(1).strip() if m else ""

        description = get_section("Description", ["Rationale", "Impact", "Audit", "Remediation"])
        rationale = get_section("Rationale", ["Impact", "Audit", "Remediation", "Default Value"])
        audit_text = get_section("Audit", ["Remediation", "Default Value", "References", "CIS Controls"])
        remediation = get_section("Remediation", ["Default Value", "References", "CIS Controls"])

        # Profiles
        profiles = ["level1"]
        if "Level 2" in block or "level 2" in block:
            profiles.append("level2")

        cmd_info = extract_audit_command(audit_text)
        checks = []
        if cmd_info["command"]:
            checks.append({
                "type": "command",
                "command": cmd_info["command"],
                "expected": cmd_info["expected"],
                "severity": "medium",
                "info": audit_text[:400]
            })
        else:
            checks.append({
                "type": "manual_review",
                "info": audit_text[:400] or description[:400],
                "severity": "medium"
            })

        controls.append({
            "id": ctrl_id,
            "title": title_text,
            "description": description[:600],
            "rationale": rationale[:600],
            "remediation": remediation[:600],
            "scoring": scoring,
            "profile": profiles,
            "checks": checks
        })

    return {
        "benchmark": {
            "id": bench_id,
            "title": title,
            "version": version,
            "technology": Path(pdf_path).parent.name,
            "os": "Multi-Platform"
        },
        "controls": controls
    }


def main():
    parser = argparse.ArgumentParser(description="Convert CIS Benchmark PDFs into HardenX/OpenCompliance YAML format")
    parser.add_argument("pdf_path", help="Path to CIS Benchmark PDF file")
    parser.add_argument("-o", "--output", help="Output YAML path")
    parser.add_argument("--pages", type=int, default=None, help="Max pages to parse (for fast sampling)")
    args = parser.parse_args()

    pdf_file = Path(args.pdf_path)
    if not pdf_file.exists():
        print(f"Error: file not found: {pdf_file}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing CIS PDF: {pdf_file.name}...")
    doc = parse_cis_pdf(str(pdf_file), max_pages=args.pages)
    count = len(doc.get("controls", []))
    print(f"[+] Found {count} controls in {doc['benchmark']['title']}")

    out_yaml = yaml.dump(doc, sort_keys=False, width=120)
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out_yaml)
        print(f"[+] Saved canonical audit YAML to: {out_path}")
    else:
        print(out_yaml[:1500])


if __name__ == "__main__":
    main()
