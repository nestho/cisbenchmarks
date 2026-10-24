#!/usr/bin/env python3
"""
cis_sync.py — Sync CIS Benchmarks (PDFs) into category/technology folders and
keep a report of what changed.

Two sources:
  * portal    — downloads.cisecurity.org public download portal (latest + the
                archives it still exposes). Needs a `laravel_session` cookie.
  * workbench — workbench.cisecurity.org full catalogue (every version /
                status, including legacy/EOL). Needs a `workbench_session`
                cookie.

It is idempotent: files already on disk (matched by filename) are skipped, so
you can run it on a schedule (cron / GitHub Actions) and it only fetches what
is new or updated. Every run appends to report.md and updates state.json.

SECRETS: never hardcode cookies in this file or commit them. Provide them via
environment variables or a git-ignored cis_config.json (see load_config()).
Cookies are your login session; treat them like a password.

Usage:
  export CIS_DOWNLOADS_SESSION=xxxxx        # laravel_session value
  export CIS_WB_SESSION=yyyyy               # workbench_session value (optional)
  python3 cis_sync.py                        # sync both available sources once
  python3 cis_sync.py --source portal        # only the public portal
  python3 cis_sync.py --source workbench     # only workbench
  python3 cis_sync.py --dry-run              # list what WOULD download
  python3 cis_sync.py --loop 86400           # re-run every N seconds

Zero third-party dependencies (standard library only).
"""

import argparse
import json
import os
import re
import sys
import time
import html
import urllib.request
import urllib.error
from pathlib import Path

# WorkBench resets connections after a burst of requests; pace + back off.
WB_PACE = 0.8        # seconds between workbench page requests
HTTP_RETRIES = 4     # retries on connection reset / timeout (not on real HTTP codes)

ROOT = Path(__file__).resolve().parent
STATE_FILE = ROOT / "state.json"
REPORT_FILE = ROOT / "report.md"
CONFIG_FILE = ROOT / "cis_config.json"

UA = "Mozilla/5.0 (cis_sync)"
DOWNLOADS = "https://downloads.cisecurity.org"
LEARN = "https://learn.cisecurity.org"
WORKBENCH = "https://workbench.cisecurity.org"


# ----------------------------------------------------------------------------
# config / secrets
# ----------------------------------------------------------------------------
def load_config():
    """Cookies come from env first, then a git-ignored cis_config.json.

    cis_config.json shape:
        { "downloads_session": "...", "workbench_session": "..." }
    """
    cfg = {"downloads_session": None, "workbench_session": None}
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text())
            cfg.update({k: data.get(k) for k in cfg if data.get(k)})
        except Exception as e:
            print(f"warn: could not read {CONFIG_FILE.name}: {e}", file=sys.stderr)
    cfg["downloads_session"] = os.environ.get("CIS_DOWNLOADS_SESSION", cfg["downloads_session"])
    cfg["workbench_session"] = os.environ.get("CIS_WB_SESSION", cfg["workbench_session"])
    return cfg


def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"runs": [], "files": {}}  # files: filename -> {source, path, first_seen}


def save_state(state):
    STATE_FILE.write_text(json.dumps(state, indent=2))


# ----------------------------------------------------------------------------
# http helpers
# ----------------------------------------------------------------------------
def _request(url, cookies=None, extra_cookies=None, binary=False, timeout=90):
    """GET url. cookies: dict of cookie name->value. Returns (status, bytes/str).

    Retries on connection reset / timeout (the sites throttle bursts), but not
    on a real HTTP status such as 401/404.
    """
    jar = []
    for d in (cookies or {}, extra_cookies or {}):
        for k, v in d.items():
            if v:
                jar.append(f"{k}={v}")
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    if jar:
        req.add_header("Cookie", "; ".join(jar))
    for attempt in range(HTTP_RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read()
                return r.status, body if binary else body.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception as e:
            if attempt == HTTP_RETRIES - 1:
                return 0, str(e).encode() if binary else str(e)
            time.sleep(3 * (attempt + 1))


def safe(name):
    name = re.sub(r'[\\/:*?"<>|]+', "_", name).strip().rstrip(".")
    return name or "x"


def is_pdf(b):
    return isinstance(b, (bytes, bytearray)) and b[:4] == b"%PDF"


# ----------------------------------------------------------------------------
# source: public portal (downloads.cisecurity.org)
# ----------------------------------------------------------------------------
def portal_targets(sess):
    """Yield (category, technology, filename, download_url, doc_id)."""
    cookies = {"laravel_session": sess}
    # the SPA mints a CSRF token in the index page meta; fetch it for the API
    status, idx = _request(DOWNLOADS + "/", cookies)
    m = re.search(r'csrf-token"\s+content="([^"]+)', idx or "")
    # technology listing is JSON grouped by category
    req = urllib.request.Request(
        DOWNLOADS + "/technology",
        headers={"User-Agent": UA, "X-Requested-With": "XMLHttpRequest",
                 "Accept": "application/json",
                 **({"X-CSRF-TOKEN": m.group(1)} if m else {}),
                 "Cookie": f"laravel_session={sess}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            groups = json.loads(r.read().decode())
    except Exception as e:
        print(f"portal: /technology failed ({e}); session likely expired", file=sys.stderr)
        return
    for cat, techs in groups.items():
        cat = cat or "Uncategorized"
        for t in techs:
            tid = t["id"]
            s2, body = _request(f"{DOWNLOADS}/technology/{tid}/benchmarks", cookies,
                                extra_cookies=None)
            try:
                benches = json.loads(body)
            except Exception:
                continue
            if not isinstance(benches, list):
                continue
            for b in benches:
                for doc in b.get("documents") or []:
                    pid, fn, did = doc.get("pardot-id"), doc.get("filename"), doc.get("id")
                    if not (pid and fn and did):
                        continue
                    pid = "/" + pid.lstrip("\\/")  # some rows have a stray backslash
                    yield safe(cat), safe(t["title"]), fn, LEARN + pid, str(did)


def portal_download(url, doc_id, sess, dest):
    cookies = {"laravel_session": sess, "documentId": str(doc_id)}
    status, body = _request(url, cookies, binary=True)
    if status == 200 and is_pdf(body):
        dest.write_bytes(body)
        return True
    return False


# ----------------------------------------------------------------------------
# source: workbench (full catalogue)
# ----------------------------------------------------------------------------
def workbench_targets(sess):
    """Yield (category, technology, filename, download_url, file_id)."""
    cookies = {"workbench_session": sess}
    status, page1 = _request(WORKBENCH + "/benchmarks?page=1", cookies)
    if status != 200:
        print(f"workbench: not authorized (HTTP {status}); session expired?", file=sys.stderr)
        return
    last = max([int(x) for x in re.findall(r"[?&]page=(\d+)", page1)] or [1])
    bench_ids = set()
    for p in range(1, last + 1):
        _, page = _request(f"{WORKBENCH}/benchmarks?page={p}", cookies)
        bench_ids.update(re.findall(r"/benchmarks/(\d+)\"", page or ""))
    for bid in sorted(bench_ids, key=int):
        time.sleep(WB_PACE)  # avoid connection-reset throttle
        _, fp = _request(f"{WORKBENCH}/benchmarks/{bid}/files", cookies)
        if not fp:
            continue
        # benchmark display name -> technology folder (strip version + [imported])
        mt = re.search(r"fa-book[^>]*></span>\s*([^<]+)", fp)
        tech = f"benchmark_{bid}"
        if mt:
            t = html.unescape(mt.group(1)).strip()
            t = re.sub(r'\s*\[imported\]', '', t)
            t = re.sub(r'\s+v(?:Next|\d[\w.\-]*)\s*$', '', t).replace('*', '').strip()
            tech = safe(t)
        # pair each download link with the filename shown in its own row
        for row in re.split(r'/files/', fp):
            m = re.match(r'(\d+)/download', row)
            if not m:
                continue
            fid = m.group(1)
            mn = re.search(r'([A-Za-z0-9][A-Za-z0-9_.\-() ]*?\.pdf)', row)
            if not mn:
                continue
            fn = mn.group(1).strip().lstrip('( ').strip()
            yield "WorkBench", tech, fn, f"{WORKBENCH}/files/{fid}/download", fid


def workbench_download(url, sess, dest):
    status, body = _request(url, {"workbench_session": sess}, binary=True)
    if status == 200 and is_pdf(body):
        dest.write_bytes(body)
        return True
    return False


# ----------------------------------------------------------------------------
# sync
# ----------------------------------------------------------------------------
def existing_filenames():
    return {p.name for p in ROOT.rglob("*.pdf")}


def sync(cfg, sources, dry_run=False):
    state = load_state()
    have = existing_filenames()
    run = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "new": [], "failed": [], "sources": sources}

    plans = []
    if "portal" in sources and cfg["downloads_session"]:
        plans.append(("portal", portal_targets(cfg["downloads_session"]),
                      lambda u, i, d: portal_download(u, i, cfg["downloads_session"], d)))
    if "workbench" in sources and cfg["workbench_session"]:
        plans.append(("workbench", workbench_targets(cfg["workbench_session"]),
                      lambda u, i, d: workbench_download(u, cfg["workbench_session"], d)))
    if not plans:
        print("No usable session cookies. Set CIS_DOWNLOADS_SESSION and/or CIS_WB_SESSION.",
              file=sys.stderr)
        return 1

    for source, targets, dl in plans:
        for cat, tech, fn, url, ident in targets:
            if fn in have:
                continue
            dest = ROOT / cat / tech / fn
            print(f"[{source}] NEW {cat}/{tech}/{fn}")
            if dry_run:
                run["new"].append(f"{cat}/{tech}/{fn}")
                have.add(fn)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dl(url, ident, dest):
                have.add(fn)
                run["new"].append(f"{cat}/{tech}/{fn}")
                state["files"][fn] = {"source": source, "path": str(dest.relative_to(ROOT)),
                                      "first_seen": run["time"]}
            else:
                run["failed"].append(f"{cat}/{tech}/{fn}")

    state["runs"].append(run)
    if not dry_run:
        save_state(state)
    write_report(state, run)
    print(f"\nDone. new={len(run['new'])} failed={len(run['failed'])} "
          f"total_on_disk={len(have)}")
    return 0


def write_report(state, run):
    lines = [f"\n## Run {run['time']}  (sources: {', '.join(run['sources'])})",
             f"- New: {len(run['new'])}",
             f"- Failed: {len(run['failed'])}",
             f"- Total PDFs on disk: {len(state['files']) or len(list(ROOT.rglob('*.pdf')))}"]
    if run["new"]:
        lines.append("\n<details><summary>new files</summary>\n")
        lines += [f"  - {x}" for x in run["new"]]
        lines.append("\n</details>")
    if run["failed"]:
        lines.append("\n<details><summary>failed (session expired or gated)</summary>\n")
        lines += [f"  - {x}" for x in run["failed"]]
        lines.append("\n</details>")
    header = "" if REPORT_FILE.exists() else "# CIS Benchmark sync report\n"
    with REPORT_FILE.open("a") as f:
        f.write(header + "\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Sync CIS Benchmarks and report changes.")
    ap.add_argument("--source", choices=["portal", "workbench", "both"], default="both")
    ap.add_argument("--dry-run", action="store_true", help="list new files, download nothing")
    ap.add_argument("--loop", type=int, metavar="SECONDS",
                    help="re-run forever every SECONDS (cron is usually better)")
    args = ap.parse_args()
    sources = ["portal", "workbench"] if args.source == "both" else [args.source]

    def once():
        cfg = load_config()
        return sync(cfg, sources, dry_run=args.dry_run)

    if args.loop:
        while True:
            try:
                once()
            except Exception as e:
                print(f"run error: {e}", file=sys.stderr)
            print(f"sleeping {args.loop}s…")
            time.sleep(args.loop)
    else:
        sys.exit(once())


if __name__ == "__main__":
    main()
