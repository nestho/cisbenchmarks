#!/usr/bin/env python3
"""
tools/batch_companion_builder.py — High-Performance Multi-Core CIS PDF Companion Generator

Scans all categories, generates companion .yaml beside each .pdf, and builds benchmarks/catalog.json.
"""

import argparse
import concurrent.futures
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from deep_cis_parser import DeepCISParser, parse_and_save

ROOT = Path(__file__).resolve().parent.parent
CATALOG_FILE = ROOT / "benchmarks" / "catalog.json"


def process_single_pdf(pdf_path: Path, force: bool = False, max_pages: Optional[int] = None) -> Optional[Dict[str, Any]]:
    yaml_path = pdf_path.with_suffix(".yaml")
    
    # Skip if already exists and valid
    if yaml_path.exists() and yaml_path.stat().st_size > 200 and not force:
        try:
            # Quick read of metadata
            meta_line = yaml_path.read_text(encoding="utf-8", errors="ignore")[:600]
            if "benchmark:" in meta_line:
                # Return basic catalog item
                return {
                    "pdf_path": str(pdf_path.relative_to(ROOT)),
                    "yaml_path": str(yaml_path.relative_to(ROOT)),
                    "status": "cached"
                }
        except Exception:
            pass

    try:
        saved_yaml = parse_and_save(pdf_path, output_path=yaml_path, max_pages=max_pages)
        return {
            "pdf_path": str(pdf_path.relative_to(ROOT)),
            "yaml_path": str(saved_yaml.relative_to(ROOT)),
            "status": "parsed"
        }
    except Exception as e:
        return {
            "pdf_path": str(pdf_path.relative_to(ROOT)),
            "error": str(e),
            "status": "failed"
        }


def extract_header_meta(yaml_file: Path) -> Optional[Dict[str, Any]]:
    try:
        lines = []
        with open(yaml_file, "r", encoding="utf-8", errors="ignore") as f:
            for _ in range(35):
                line = f.readline()
                if not line or line.startswith("controls:"):
                    break
                lines.append(line)
        header_text = "".join(lines)
        if "benchmark:" not in header_text:
            return None
        import yaml
        raw = yaml.safe_load(header_text)
        if not raw or "benchmark" not in raw:
            return None
        return raw.get("benchmark")
    except Exception:
        return None


def build_catalog(pdf_files: Optional[List[Path]] = None) -> List[Dict[str, Any]]:
    """Build benchmarks/catalog.json summarizing all companion YAML benchmarks across the repo."""
    catalog = []
    
    # If not provided, scan all PDFs and companion YAMLs across all subdirectories
    all_yamls = []
    for f in ROOT.rglob("*.yaml"):
        p = str(f)
        if any(skip in p for skip in [".git", "node_modules", ".cache", "platform/frontend/dist", "standards"]):
            continue
        all_yamls.append(f)

    all_yamls.sort()

    for yaml_file in all_yamls:
        if yaml_file.stat().st_size < 100:
            continue
        try:
            bm = extract_header_meta(yaml_file)
            if not bm:
                continue

            pdf = yaml_file.with_suffix(".pdf")
            if not pdf.exists():
                pdf = yaml_file.with_suffix(".PDF")

            catalog.append({
                "id": bm.get("id"),
                "title": bm.get("title"),
                "version": bm.get("version"),
                "category": bm.get("category", pdf.parent.parent.name),
                "technology": bm.get("technology", pdf.parent.name),
                "os": bm.get("os", "Universal"),
                "controls_count": bm.get("controls_count", 0),
                "pdf_path": str(pdf.relative_to(ROOT)),
                "yaml_path": str(yaml_file.relative_to(ROOT)),
            })
        except Exception:
            continue

    catalog.sort(key=lambda x: (x.get("category", ""), x.get("technology", ""), x.get("title", "")))
    CATALOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CATALOG_FILE.write_text(json.dumps(catalog, indent=2), encoding="utf-8")
    return catalog


def main():
    p = argparse.ArgumentParser(description="Batch generate companion YAMLs for all CIS PDFs")
    p.add_argument("--category", help="Specific category folder (e.g. 'Operating Systems', 'Server Software')")
    p.add_argument("--workers", type=int, default=os.cpu_count() or 4, help="Parallel worker processes")
    p.add_argument("--force", action="store_true", help="Re-parse even if companion YAML already exists")
    p.add_argument("--pages", type=int, default=None, help="Max pages per PDF (for quick verification runs)")
    p.add_argument("--catalog-only", action="store_true", help="Only rebuild catalog.json from existing YAMLs")
    args = p.parse_args()

    search_dir = ROOT / args.category if args.category else ROOT
    print(f"[*] Scanning for CIS PDFs in: {search_dir}...")
    
    # Exclude system and vendor dirs
    pdf_list = []
    for ext in ["*.pdf", "*.PDF"]:
        for f in search_dir.rglob(ext):
            p_str = str(f)
            if any(skip in p_str for skip in [".git", "node_modules", ".cache", "platform/frontend/dist"]):
                continue
            pdf_list.append(f)

    pdf_list.sort()
    print(f"[+] Found {len(pdf_list)} CIS PDFs to process.")

    if not args.catalog_only:
        start_time = time.time()
        print(f"[*] Starting parallel companion generation using {args.workers} workers...")
        
        parsed = 0
        cached = 0
        failed = 0

        with concurrent.futures.ProcessPoolExecutor(max_workers=args.workers) as executor:
            future_to_pdf = {
                executor.submit(process_single_pdf, pdf, args.force, args.pages): pdf
                for pdf in pdf_list
            }
            for idx, future in enumerate(concurrent.futures.as_completed(future_to_pdf), 1):
                res = future.result()
                status = res.get("status")
                if status == "parsed":
                    parsed += 1
                elif status == "cached":
                    cached += 1
                elif status == "failed":
                    failed += 1
                
                if idx % 10 == 0 or idx == len(pdf_list):
                    elapsed = time.time() - start_time
                    print(f"[{idx}/{len(pdf_list)}] parsed={parsed} cached={cached} failed={failed} ({elapsed:.1f}s)")

        print(f"[+] Companion generation completed: {parsed} parsed, {cached} cached, {failed} failed in {time.time() - start_time:.1f}s")

    print("[*] Compiling unified catalog: benchmarks/catalog.json...")
    catalog = build_catalog(pdf_list)
    print(f"[+] Catalog compiled: {len(catalog)} benchmarks registered in {CATALOG_FILE.relative_to(ROOT)}.")


if __name__ == "__main__":
    main()
