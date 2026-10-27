"""Full OS Security Assessment workbook — template-faithful, client-ready."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional
import os
import re
import tempfile
from copy import copy

from openpyxl import load_workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

from .engine import AnalysisResult
from .report import _finding_groups, _group_severity, _group_status, _group_class
from .security_guidance import (
    security_comment_connection,
    security_comment_user,
    security_comment_route,
    security_comment_process,
    security_comment_cron,
    security_comment_vulnerability,
    remediation_for_finding,
    vendor_advisory_url,
)

# Industry-standard severity palette (Critical → Info)
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_FILL = {
    "Critical": PatternFill("solid", fgColor="9C0006"),  # dark red
    "High": PatternFill("solid", fgColor="ED7D31"),      # orange
    "Medium": PatternFill("solid", fgColor="FFC000"),    # gold
    "Low": PatternFill("solid", fgColor="70AD47"),       # green
    "Info": PatternFill("solid", fgColor="5B9BD5"),      # blue
}
SEVERITY_FONT = {
    "Critical": Font(name="Calibri", size=11, bold=True, color="FFFFFF"),
    "High": Font(name="Calibri", size=11, bold=True, color="FFFFFF"),
    "Medium": Font(name="Calibri", size=11, bold=True, color="000000"),
    "Low": Font(name="Calibri", size=11, bold=True, color="FFFFFF"),
    "Info": Font(name="Calibri", size=11, bold=True, color="FFFFFF"),
}

THIN = Side(style="thin", color="B4B4B4")
THIN_BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
CENTER = Alignment(horizontal="center", vertical="center", wrap_text=True)
LEFT = Alignment(horizontal="left", vertical="center", wrap_text=True)
RIGHT = Alignment(horizontal="right", vertical="center", wrap_text=True)

_PERSIAN_RE = re.compile(r"[\u0600-\u06FF]")


def _is_persian(value: Any) -> bool:
    return bool(_PERSIAN_RE.search(str(value or "")))


def _align_for(value: Any, *, prefer_center: bool = False) -> Alignment:
    if prefer_center:
        return CENTER
    if _is_persian(value):
        return RIGHT
    return LEFT


def _resolve_writable_cell(ws: Worksheet, row: int, col: int):
    """Return a writable cell; if (row,col) is inside a merge, return the top-left cell."""
    cell = ws.cell(row, col)
    if type(cell).__name__ != "MergedCell":
        return cell
    for m in ws.merged_cells.ranges:
        if m.min_row <= row <= m.max_row and m.min_col <= col <= m.max_col:
            return ws.cell(m.min_row, m.min_col)
    return None


def _unmerge_area(ws: Worksheet, min_row: int, max_row: int, min_col: int = 1, max_col: int = 20) -> None:
    """Unmerge any ranges intersecting the given rectangle so cells become writable."""
    stale = []
    for m in list(ws.merged_cells.ranges):
        if m.max_row < min_row or m.min_row > max_row:
            continue
        if m.max_col < min_col or m.min_col > max_col:
            continue
        stale.append(str(m))
    for coord in stale:
        try:
            ws.unmerge_cells(coord)
        except Exception:
            pass


def _set_cell(
    ws: Worksheet,
    row: int,
    col: int,
    value: Any,
    *,
    border: bool = False,
    align: Optional[Alignment] = None,
    fill: Optional[PatternFill] = None,
    font: Optional[Font] = None,
    prefer_center: bool = False,
) -> None:
    cell = _resolve_writable_cell(ws, row, col)
    if cell is None:
        return
    try:
        cell.value = value
    except AttributeError:
        # Last resort: unmerge intersecting and retry
        _unmerge_area(ws, row, row, col, col)
        cell = ws.cell(row, col)
        try:
            cell.value = value
        except AttributeError:
            return
    if border:
        try:
            cell.border = THIN_BORDER
        except Exception:
            pass
    if fill is not None:
        try:
            cell.fill = fill
        except Exception:
            pass
    if font is not None:
        try:
            cell.font = font
        except Exception:
            pass
    if align is not None:
        try:
            cell.alignment = align
        except Exception:
            pass
    elif value is not None and str(value).strip() != "":
        try:
            cell.alignment = _align_for(value, prefer_center=prefer_center)
        except Exception:
            pass


def _clear_range(ws: Worksheet, start: int, end: int, cols: int) -> None:
    end = max(start, end)
    _unmerge_area(ws, start, end, 1, cols)
    for r in range(start, end + 1):
        for c in range(1, cols + 1):
            cell = ws.cell(r, c)
            if type(cell).__name__ == "MergedCell":
                continue
            try:
                cell.value = None
            except AttributeError:
                pass


def _copy_row_style(ws: Worksheet, src_row: int, dst_row: int, cols: int) -> None:
    """Copy font/fill/border/alignment from src_row onto dst_row (values untouched)."""
    for c in range(1, cols + 1):
        src = ws.cell(src_row, c)
        dst = ws.cell(dst_row, c)
        if type(dst).__name__ == "MergedCell":
            continue
        if src.has_style:
            dst.font = copy(src.font)
            dst.border = copy(src.border)
            dst.fill = copy(src.fill)
            dst.alignment = copy(src.alignment)
            dst.number_format = src.number_format


def _find_row_by_title(ws: Worksheet, *titles: str, max_scan: int = 5000) -> Optional[int]:
    limit = max(ws.max_row or 1, 1)
    limit = min(limit, max_scan)
    for r in range(1, limit + 1):
        v = str(ws.cell(r, 1).value or "").strip()
        if not v:
            continue
        for title in titles:
            if v == title or title in v:
                return r
    return None



def _remerge_title(ws: Worksheet, title_row: int, end_col: int) -> None:
    """Ensure section title spans A:end_col (repair merges after insert_rows)."""
    if title_row is None or title_row < 1:
        return
    # Drop any merge that intersects this title row on column A band
    stale = []
    for m in list(ws.merged_cells.ranges):
        if m.min_row <= title_row <= m.max_row and m.min_col <= 1 <= m.max_col:
            stale.append(str(m))
        elif m.min_row == title_row:
            stale.append(str(m))
    for coord in stale:
        try:
            ws.unmerge_cells(coord)
        except Exception:
            pass
    try:
        ws.merge_cells(start_row=title_row, start_column=1, end_row=title_row, end_column=end_col)
    except Exception:
        pass
    # Restyle title cell
    cell = ws.cell(title_row, 1)
    if type(cell).__name__ != "MergedCell":
        cell.font = Font(name="Calibri", size=12, bold=True, color="1F4E78")
        cell.alignment = Alignment(horizontal="left", vertical="center")
        cell.fill = PatternFill("solid", fgColor="D6DCE4")



def _resize_table(ws: Worksheet, name_substr: str, start_row: int, end_row: int, start_col: int, end_col: int) -> None:
    """Expand/shrink an Excel Table so banded row styles cover all data."""
    if end_row < start_row:
        end_row = start_row
    ref = f"{get_column_letter(start_col)}{start_row}:{get_column_letter(end_col)}{end_row}"
    for name in list(ws.tables.keys()):
        if name_substr.lower() in name.lower() or name_substr.lower() in str(getattr(ws.tables[name], "displayName", "")).lower():
            try:
                ws.tables[name].ref = ref
                if ws.tables[name].autoFilter is not None:
                    ws.tables[name].autoFilter.ref = ref
            except Exception:
                pass
            return


def _apply_band_rows(ws: Worksheet, start: int, count: int, cols: int, color_a: str = "F2F2F2", color_b: str = "FFFFFF") -> None:
    """Uniform professional banded rows (overrides leftover sample fills)."""
    fill_a = PatternFill("solid", fgColor=color_a)
    fill_b = PatternFill("solid", fgColor=color_b)
    for i in range(count):
        r = start + i
        fill = fill_a if i % 2 == 0 else fill_b
        for c in range(1, cols + 1):
            cell = ws.cell(r, c)
            if type(cell).__name__ == "MergedCell":
                continue
            cell.fill = fill
            cell.border = THIN_BORDER
            if cell.alignment is None or cell.alignment.horizontal is None:
                cell.alignment = CENTER


def _ensure_data_capacity(
    ws: Worksheet,
    data_start: int,
    next_section_row: int,
    needed: int,
) -> int:
    """Ensure [data_start, next_section) has at least `needed` rows.

    Inserts rows just above next_section so merged section titles shift correctly.
    Returns the (possibly updated) next_section_row.
    """
    capacity = max(0, next_section_row - data_start)
    if needed <= capacity:
        return next_section_row
    extra = needed - capacity
    ws.insert_rows(next_section_row, extra)
    return next_section_row + extra


def _write_table_rows(
    ws: Worksheet,
    start: int,
    rows: list[list[Any]],
    cols: int,
    *,
    style_src_row: Optional[int] = None,
    center_cols: Optional[set[int]] = None,
) -> None:
    center_cols = center_cols or set()
    for i, row in enumerate(rows):
        r = start + i
        if style_src_row is not None:
            _copy_row_style(ws, style_src_row, r, cols)
        for j in range(cols):
            val = row[j] if j < len(row) else None
            prefer = (j + 1) in center_cols
            _set_cell(
                ws, r, j + 1, val,
                border=True,
                prefer_center=prefer,
            )


# ---------------------------------------------------------------------------
# Collector parsers
# ---------------------------------------------------------------------------

def _section_body(text: str, *names: str) -> str:
    bodies: list[str] = []
    for name in names:
        pat = re.compile(
            r"(?im)^={10,}\s*\n\s*SECTION:\s*" + re.escape(name) + r"\s*\n={10,}\s*\n"
            r"(.*?)"
            r"(?=^={10,}\s*$|^\s*SECTION:\s*|\Z)",
            re.S,
        )
        for m in pat.finditer(text):
            bodies.append(m.group(1))
        pat2 = re.compile(
            r"(?im)^=====+\s*" + re.escape(name) + r"\s*=====+\s*\n(.*?)(?=^=====+|\Z)",
            re.S,
        )
        for m in pat2.finditer(text):
            bodies.append(m.group(1))
    return "\n".join(bodies)


def _meta(text: str, key: str) -> str:
    m = re.search(rf"(?m)^META\|{re.escape(key)}\|(.+)$", text)
    return m.group(1).strip() if m else ""


def _split_addr(addr: str) -> tuple[str, str]:
    addr = (addr or "").strip()
    if addr in ("*", "*:*", ""):
        return "*", "*"
    if addr.startswith("["):
        m = re.match(r"\[([^\]]+)\]:(\d+|\*)$", addr)
        if m:
            return m.group(1), m.group(2)
    if addr.count(":") == 1:
        a, b = addr.rsplit(":", 1)
        return a or "0.0.0.0", b
    if ":" in addr:
        a, b = addr.rsplit(":", 1)
        if b.isdigit() or b == "*":
            return a, b
    return addr, "*"


def parse_connections(text: str) -> list[dict[str, Any]]:
    body = _section_body(text, "ALL NETWORK CONNECTIONS", "NETWORK CONNECTIONS")
    if not body:
        m = re.search(r"(?m)^(?:Active Internet connections|Proto\s+Recv-Q|Netid\s+State).*$", text)
        if m:
            body = text[m.start(): m.start() + 80000]
    conns: list[dict[str, Any]] = []
    for ln in (body or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("Active") or ln.startswith("Proto") or ln.startswith("Netid"):
            continue
        parts = ln.split()
        if len(parts) < 5:
            continue
        if parts[0] in ("tcp", "tcp6", "udp", "udp6") and len(parts) >= 6:
            try:
                recv_q, send_q = int(parts[1]), int(parts[2])
            except ValueError:
                # ss format: tcp LISTEN 0 128 ...
                if re.match(r"^[A-Z-]+$", parts[1]) and len(parts) >= 6:
                    try:
                        recv_q, send_q = int(parts[2]), int(parts[3])
                    except ValueError:
                        continue
                    local, peer = parts[4], parts[5]
                    lip, lport = _split_addr(local)
                    dip, dport = _split_addr(peer)
                    user = ""
                    um = re.search(r'users:\(\("([^"]+)"', ln)
                    if um:
                        user = um.group(1)
                    conns.append({
                        "protocol": parts[0], "recv_q": recv_q, "send_q": send_q,
                        "src_ip": lip, "src_port": lport, "dst_ip": dip, "dst_port": dport,
                        "state": parts[1], "user": user, "inode": "",
                    })
                continue
            local, peer = parts[3], parts[4]
            state = parts[5] if len(parts) > 5 else ""
            user = parts[6] if len(parts) > 6 else ""
            if user == "-":
                user = ""
            lip, lport = _split_addr(local)
            dip, dport = _split_addr(peer)
            conns.append({
                "protocol": parts[0], "recv_q": recv_q, "send_q": send_q,
                "src_ip": lip, "src_port": lport, "dst_ip": dip, "dst_port": dport,
                "state": state, "user": user, "inode": "",
            })
    return conns


def parse_iptables(text: str) -> list[str]:
    lines: list[str] = []
    for section in (
        "FIREWALL DETECTION",
        "IPTABLES SAVE COUNTERS",
        "IPTABLES SAVE",
        "IPTABLES",
        "IP6TABLES SAVE COUNTERS",
        "NFTABLES",
        "FIREWALL",
        "FIREWALLD",
        "FIREWALL END",
    ):
        body = _section_body(text, section)
        for ln in (body or "").splitlines():
            ln = ln.rstrip()
            if not ln:
                continue
            lines.append(ln)
    # de-dup preserve order
    seen = set()
    out = []
    for ln in lines:
        if ln in seen:
            continue
        seen.add(ln)
        out.append(ln)
    return out


def parse_neighbors(text: str) -> list[dict[str, str]]:
    body = _section_body(text, "NEIGHBORS")
    rows = []
    seen = set()
    for ln in (body or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("CMD:") or ln.startswith("RC=") or ln.startswith("=====") or ln.startswith("IP"):
            continue
        # ip neigh: 10.x.x.x dev eth0 lladdr aa:bb ... REACHABLE
        m = re.match(r"(\S+)\s+dev\s+(\S+)(?:\s+lladdr\s+(\S+))?(?:\s+(\S+))?", ln)
        if m:
            key = (m.group(1), m.group(2), m.group(3) or "")
            if key not in seen:
                seen.add(key)
                rows.append({"interface": m.group(2), "ip": m.group(1), "mac": m.group(3) or "", "state": m.group(4) or ""})
            continue
        # arp -an: ? (10.x.x.x) at aa:bb:cc on eth0
        m = re.match(r".*\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)\s+.*\bon\s+(\S+)", ln)
        if m:
            mac = m.group(2)
            if mac == "<incomplete>":
                mac = ""
            key = (m.group(1), m.group(3), mac)
            if key not in seen:
                seen.add(key)
                rows.append({"interface": m.group(3), "ip": m.group(1), "mac": mac, "state": ""})
            continue
        # /proc/net/arp: IP * HW type Flags HW address Mask Device
        parts = ln.split()
        if len(parts) >= 6 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]) and ":" in parts[3]:
            key = (parts[0], parts[-1], parts[3])
            if key not in seen:
                seen.add(key)
                rows.append({"interface": parts[-1], "ip": parts[0], "mac": parts[3], "state": parts[2]})
    return rows


def parse_routes(text: str) -> list[dict[str, str]]:
    routes = []
    for section in ("IPv4 ROUTING", "IPv6 ROUTING", "ROUTING", "POLICY ROUTING"):
        body = _section_body(text, section)
        for ln in (body or "").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("Kernel") or ln.startswith("Destination") or ln.startswith("Next Hop"):
                continue
            # ip route style
            m = re.match(r"default\s+via\s+(\S+)\s+dev\s+(\S+)", ln)
            if m:
                routes.append({"destination": "default", "gateway": m.group(1), "interface": m.group(2)})
                continue
            m = re.match(r"default\s+dev\s+(\S+)", ln)
            if m:
                routes.append({"destination": "default", "gateway": "", "interface": m.group(1)})
                continue
            m = re.match(r"(\S+)\s+via\s+(\S+)\s+dev\s+(\S+)", ln)
            if m:
                routes.append({"destination": m.group(1), "gateway": m.group(2), "interface": m.group(3)})
                continue
            m = re.match(r"(\S+)\s+dev\s+(\S+)", ln)
            if m and not ln.lower().startswith("broadcast"):
                routes.append({"destination": m.group(1), "gateway": "", "interface": m.group(2)})
                continue
            # netstat -rn / route -n IPv6 style: Dest  NextHop  Flag Met Ref Use If
            parts = ln.split()
            if len(parts) >= 7 and re.match(r"^[0-9a-fA-F:\./]+$", parts[0]):
                routes.append({
                    "destination": parts[0],
                    "gateway": parts[1] if parts[1] != "::" else "",
                    "interface": parts[-1],
                })
                continue
            if len(parts) >= 8 and re.match(r"^[0-9.]+$", parts[0]):
                # Destination Gateway Genmask Flags Metric Ref Use Iface
                routes.append({
                    "destination": parts[0],
                    "gateway": parts[1] if parts[1] not in ("0.0.0.0", "*") else "",
                    "interface": parts[-1],
                })
    # de-dup
    seen = set()
    out = []
    for r in routes:
        key = (r["destination"], r["gateway"], r["interface"])
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def parse_users(text: str) -> list[dict[str, str]]:
    body = _section_body(text, "LOCAL USERS", "USERS")
    users = []
    for m in re.finditer(r"(?m)^USER\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]*)\|([^|]*)\|([^|]*)$", body or text):
        users.append({
            "username": m.group(1).strip(), "uid": m.group(2).strip(), "gid": m.group(3).strip(),
            "gecos": m.group(4).strip(), "home": m.group(5).strip(), "shell": m.group(6).strip(),
        })
    if users:
        return users
    for ln in (body or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#") or ln.startswith("=") or ln.startswith("SECTION"):
            continue
        if ln.count(":") < 6:
            continue
        parts = ln.split(":")
        if not parts[0] or not parts[2].isdigit():
            continue
        shell = parts[6] if len(parts) > 6 else ""
        home = parts[5] if len(parts) > 5 else ""
        if "\n" in shell:
            shell = shell.split("\n")[0].strip()
        if any(tok in shell for tok in ("SECTION", "====", "LOCAL GROUPS", "PASSWORD")):
            shell = ""
        if any(tok in home for tok in ("SECTION", "====")):
            home = ""
        if len(shell) > 64 or (shell and not shell.startswith("/")):
            shell = shell.split()[0] if shell.startswith("/") else ""
        users.append({
            "username": parts[0], "uid": parts[2], "gid": parts[3],
            "gecos": parts[4], "home": home, "shell": shell,
        })
    return users


def parse_groups(text: str) -> list[dict[str, str]]:
    body = _section_body(text, "LOCAL GROUPS", "GROUPS")
    groups = []
    for m in re.finditer(r"(?m)^GROUP\|([^|]+)\|([^|]+)\|([^|]*)$", body or text):
        groups.append({"name": m.group(1).strip(), "gid": m.group(2).strip(), "members": m.group(3).strip()})
    if groups:
        return groups
    for ln in (body or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#") or "SECTION" in ln or ln.startswith("="):
            continue
        if ln.count(":") < 2:
            continue
        parts = ln.split(":")
        if len(parts) >= 3 and parts[1].isdigit():
            members = parts[3] if len(parts) > 3 else ""
            if "\n" in members:
                members = members.split("\n")[0].strip()
            if any(tok in members for tok in ("SECTION", "====", "WHEEL GROUP", "PASSWORD", "----")):
                members = ""
            groups.append({"name": parts[0], "gid": parts[1], "members": members})
    return groups


def parse_mac(text: str) -> list[str]:
    macs = []
    for m in re.finditer(r"(?:link/ether|ether)\s+([0-9a-fA-F:]{11,17})", text):
        mac = m.group(1).lower()
        if mac not in macs and mac != "00:00:00:00:00:00":
            macs.append(mac)
    # IFACE|eth0|mac=aa:bb:... from v6.4+
    for m in re.finditer(r"(?m)^IFACE\|[^|]+\|mac=([0-9a-fA-F:]{11,17})", text):
        mac = m.group(1).lower()
        if mac not in macs and mac not in ("00:00:00:00:00:00", ""):
            macs.append(mac)
    return macs



def parse_iface_ip_map(text: str) -> dict[str, str]:
    """Map IP address -> interface name from INTERFACES section (multi-format)."""
    body = _section_body(text, "INTERFACES") or text
    mapping: dict[str, str] = {}
    _BAD_IFACE = {
        "forever", "preferred_lft", "valid_lft", "global", "host", "link",
        "noprefixroute", "dynamic", "scope", "brd", "inet", "inet6",
        "metric", "proto", "kernel", "static",
    }

    def _put(ip: str, iface: str, *, overwrite: bool = False) -> None:
        ip = (ip or "").strip().rstrip(":")
        iface = (iface or "").strip().rstrip(":").rstrip("\\")
        if not ip or not iface:
            return
        if ip.lower().startswith("fe80"):
            return
        if iface.lower() in _BAD_IFACE or iface.isdigit():
            return
        if not overwrite and ip in mapping:
            return
        mapping[ip] = iface

    # ip -o -4/-6 addr: 2: eth0    inet 10.x.x.x/25 ...
    for m in re.finditer(
        r"(?m)^\s*\d+:\s*(\S+)\s+inet6?\s+([^/\s]+)",
        body,
    ):
        _put(m.group(2), m.group(1), overwrite=True)

    # ip -br address: eth0 UP 10.x/25 fe80::...
    for m in re.finditer(
        r"(?m)^(\S+)\s+(?:UP|DOWN|UNKNOWN|LOWERLAYERDOWN)\s+(.+)$",
        body,
    ):
        iface, rest = m.group(1), m.group(2)
        if iface.lower() in _BAD_IFACE:
            continue
        for im in re.finditer(r"(\d+\.\d+\.\d+\.\d+)", rest):
            _put(im.group(1), iface, overwrite=True)
        for im in re.finditer(r"([0-9a-fA-F:]+::[0-9a-fA-F:]*)", rest):
            _put(im.group(1), iface, overwrite=True)

    # IFACE|eth0|mac=..|ipv4=10.x
    for m in re.finditer(r"(?m)^IFACE\|([^|]+)\|(.+)$", body):
        iface, rest = m.group(1), m.group(2)
        for im in re.finditer(r"(?:ipv4|ipv6|ip)=([^|/\s]+)", rest, re.I):
            _put(im.group(1), iface, overwrite=True)

    # Trailing device after scope (only if not already mapped): "... scope global eth0"
    for m in re.finditer(
        r"(?m)\binet6?\s+([^/\s]+)/\d+[^\n]*?\bscope\s+\S+\s+(\S+)",
        body,
    ):
        _put(m.group(1), m.group(2), overwrite=False)

    return mapping


def _local_ips_from_map(iface_map: dict[str, str]) -> set[str]:
    return set(iface_map.keys()) | {"127.0.0.1", "::1"}


def _iface_resolver(iface_map: dict[str, str]):
    """Return a function IP -> interface using exact map + longest-prefix heuristic."""
    # Build simple /24-ish buckets from known host IPs for same-subnet match
    prefixes: list[tuple[str, str]] = []
    for ip, iface in iface_map.items():
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            parts = ip.split(".")
            prefixes.append((".".join(parts[:3]) + ".", iface))
            prefixes.append((".".join(parts[:2]) + ".", iface))  # weaker /16 fallback
    # prefer longer prefix
    prefixes.sort(key=lambda x: len(x[0]), reverse=True)

    def resolve(ip: str) -> str:
        ip = str(ip or "").strip()
        if not ip or ip in ("*", "0.0.0.0", "::", "*:*"):
            return "all"  # listening on all interfaces
        if ip in ("127.0.0.1", "::1", "localhost"):
            return "lo"
        if ip in iface_map:
            return iface_map[ip]
        for pref, iface in prefixes:
            if ip.startswith(pref):
                return iface
        if ip.startswith("172.17."):
            return "docker0"
        if ip.startswith("fe80:"):
            return "link-local"
        return "n/a"

    return resolve


def _outbound_summary(conns: list[dict], local_ips: set[str]) -> list[str]:
    """Unique outbound destinations as proto/port->ip for Host Info Outband column."""
    out, seen = [], set()
    for c in conns:
        st = str(c.get("state", "")).upper()
        if st not in ("ESTABLISHED", "SYN_SENT", "TIME_WAIT"):
            continue
        sip = str(c.get("src_ip") or "")
        dip = str(c.get("dst_ip") or "")
        dport = str(c.get("dst_port") or "")
        proto = str(c.get("protocol") or "tcp")
        if not dip or dip in ("*", "0.0.0.0", "::"):
            continue
        # skip pure local-local
        if dip in local_ips or dip.startswith("127."):
            continue
        key = f"{proto}/{dport}->{dip}"
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
        if len(out) >= 60:
            break
    return out


def _security_comment_conn(c: dict, local_ips: set[str], os_family: str = "redhat") -> str:
    """Authoritative CIS/RHEL-aligned note — empty if no real finding."""
    return security_comment_connection(c, local_ips, os_family=os_family)


def _security_comment_user(u: dict, os_family: str = "redhat") -> str:
    return security_comment_user(u, os_family=os_family)


def _security_comment_route(r: dict) -> str:
    return security_comment_route(r)


def _security_comment_process(path: str) -> str:
    return security_comment_process(path)



def parse_soc_agents(text: str) -> list[str]:
    agents = []
    for m in re.finditer(r"(?m)^AGENT\|found\|name=([^|]+)", text):
        agents.append(m.group(1).strip())
    for m in re.finditer(r"(?m)^AGENT_SVC\|([^|]+)\|active=active", text):
        agents.append(m.group(1).strip())
    # unique preserve order
    out = []
    for a in agents:
        if a and a not in out:
            out.append(a)
    return out


def parse_cron(text: str) -> list[str]:
    jobs = []
    body = _section_body(text, "CRON JOBS", "CRON")
    for ln in (body or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#") or ln.startswith("=") or ln.startswith("SECTION"):
            continue
        if re.match(r"^[@0-9*]", ln) or re.match(r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+", ln):
            jobs.append(ln)
    # systemd timers as scheduled jobs when crontab empty
    body = _section_body(text, "SYSTEMD TIMERS")
    for ln in (body or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("NEXT") or ln.startswith("n/a") or ln.startswith("UNIT FILE"):
            continue
        if ".timer" in ln:
            jobs.append("[systemd-timer] " + re.sub(r"\s+", " ", ln))
        elif ln.endswith("listed.") or ln.endswith("listed"):
            continue
        elif re.match(r"\S+\.timer\s+\S+", ln):
            jobs.append("[timer-unit] " + re.sub(r"\s+", " ", ln))
    return jobs



def parse_environment(text: str) -> list[dict[str, str]]:
    body = _section_body(text, "ENVIRONMENT - COLLECTOR PROCESS", "ENVIRONMENT", "ENV")
    rows = []
    for ln in (body or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("=") or ln.startswith("SECTION"):
            continue
        if ln.startswith("Path=") and "Owner=" in ln:
            rows.append({"user": "path-perm", "env": ln, "comment": "PATH directory permissions"})
            continue
        if "=" in ln and not ln.startswith(" "):
            k, _, v = ln.partition("=")
            if k and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", k):
                rows.append({"user": "", "env": f"{k}={v}", "comment": ""})
    return rows


def parse_root_procs(text: str) -> list[dict[str, str]]:
    body = _section_body(text, "ROOT PROCESSES", "PROCESSES")
    rows = []
    seen = set()
    # Preferred structured lines from v6.3+
    for m in re.finditer(r"(?m)^PID=(\d+)\s+EXE=(\S+)(?:\s+CMD=(.*))?$", body or text):
        pid, exe, cmd = m.group(1), m.group(2), (m.group(3) or "").strip()
        path = exe if not exe.startswith("(") else (cmd or exe)
        if pid not in seen:
            seen.add(pid)
            rows.append({"pid": pid, "path": path or exe})
    if rows:
        return rows
    # ps table with headers: USER PID PPID STAT STARTED COMM ARGS
    header_seen = False
    for ln in (body or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("="):
            continue
        if re.match(r"(?i)^USER\s+PID\s+", ln) or re.match(r"(?i)^pid\s+ppid", ln):
            header_seen = True
            continue
        parts = ln.split(None, 6)
        if len(parts) >= 6 and parts[1].isdigit():
            # user pid ppid stat lstart...  -> take pid and remaining args
            pid = parts[1]
            path = parts[-1] if len(parts) >= 7 else parts[5]
            if pid not in seen:
                seen.add(pid)
                rows.append({"pid": pid, "path": path})
            continue
        if len(parts) >= 2 and parts[0].isdigit() and not header_seen:
            pid = parts[0]
            path = " ".join(parts[1:])
            if pid not in seen:
                seen.add(pid)
                rows.append({"pid": pid, "path": path})
    return rows


def _listen_ports(conns: list[dict]) -> list[str]:
    out, seen = [], set()
    for c in conns:
        st = str(c.get("state", "")).upper()
        if st in ("LISTEN", "UNCONN"):
            p = f"{c.get('protocol')}/{c.get('src_port')}"
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


def _service_hint(port: str, proto: str, state: str) -> str:
    if str(state).upper() not in ("LISTEN", "UNCONN"):
        return ""
    known = {
        "22": "SSH", "25": "SMTP", "53": "DNS", "80": "HTTP", "111": "RPC",
        "443": "HTTPS", "5432": "PostgreSQL", "3306": "MySQL", "6379": "Redis",
        "8080": "HTTP-alt", "8443": "HTTPS-alt", "9090": "Prometheus/Cockpit",
        "9093": "Alertmanager", "9100": "node-exporter", "8500": "Consul",
        "8300": "Consul-server", "8301": "Consul-serf", "8600": "Consul-DNS",
        "6789": "Ceph/monitor", "2049": "NFS", "1234": "Custom",
    }
    return known.get(str(port), "")


# ---------------------------------------------------------------------------
# Findings → template rows (sorted Critical → Info)
# ---------------------------------------------------------------------------

def _findings_to_template_rows(result: AnalysisResult) -> list[list[Any]]:
    groups = _finding_groups(result)
    rows: list[list[Any]] = []
    for items in groups:
        if not items:
            continue
        cves = list(dict.fromkeys(x.cve for x in items if x.cve))
        components = list(dict.fromkeys(x.package_name for x in items if x.package_name))
        installed = list(dict.fromkeys(
            f"{x.package_name}={x.installed_evr}" if x.installed_evr else x.package_name for x in items
        ))
        fixed = list(dict.fromkeys(f"{x.package_name}={x.fixed_evr}" for x in items if x.fixed_evr))
        advisories = list(dict.fromkeys(x.evidence.advisory for x in items if x.evidence.advisory))
        desc = max((x.description for x in items if x.description), key=len, default="")
        # Vendor-grade remediation from advisory + package manager command
        os_family = (getattr(getattr(result, "inventory", None), "os", None) and result.inventory.os.family) or "redhat"
        os_version = (getattr(getattr(result, "inventory", None), "os", None) and result.inventory.os.version) or ""
        pkg0 = components[0] if components else ""
        adv0 = advisories[0] if advisories else ""
        fixed0 = ""
        for x in items:
            if x.fixed_evr:
                fixed0 = f"{x.package_name}={x.fixed_evr}" if x.package_name else x.fixed_evr
                break
        installed0 = ""
        for x in items:
            if x.installed_evr:
                installed0 = x.installed_evr
                break
        raw_solutions = list(dict.fromkeys(x.solution.strip() for x in items if x.solution and x.solution.strip()))
        solution = remediation_for_finding(
            package=pkg0,
            advisory=adv0,
            fixed_evr=fixed0.split("=", 1)[-1] if fixed0 else "",
            installed_evr=installed0,
            solution="\n".join(raw_solutions),
            os_family=str(os_family),
            os_version=str(os_version),
        )
        name_bits = []
        if components:
            name_bits.append(", ".join(components[:8]))
        if advisories:
            name_bits.append(advisories[0])
        name = " — ".join(name_bits) if name_bits else (_group_class(items) or "Finding")
        status = _group_status(items)
        conf = "; ".join(dict.fromkeys(x.confidence for x in items if x.confidence))
        kev_flag = any(getattr(x, "kev", False) for x in items)
        kev = "Yes" if kev_flag else "No"
        src = "\n".join(dict.fromkeys(x.evidence.source for x in items if x.evidence.source))
        severity = _normalize_severity(_group_severity(items))
        comments = security_comment_vulnerability(
            severity=severity,
            package=pkg0,
            advisory=adv0,
            cves=cves,
            kev=kev_flag,
            status=str(status),
            os_family=str(os_family),
        )
        if not comments:
            comments = f"Status={status} | Confidence={conf} | CISA KEV={kev} | Source={src}"
        else:
            comments = f"{comments} | Status={status} | Confidence={conf}"
        severity = _normalize_severity(_group_severity(items))
        rows.append([
            0,  # NUM filled after sort
            "\n".join(cves),
            severity,
            name,
            desc,
            solution,
            "\n".join(components),
            "\n".join(installed),
            "\n".join(fixed),
            "\n".join(advisories),
            "",
            "",
            "",
            "",
            "",
            comments,
            "",
            "",
            "",
            "",
            "",
        ])
    # Sort Critical → Info, stable within same severity
    rows.sort(key=lambda r: SEVERITY_ORDER.get(_normalize_severity(r[2]), 9))
    for i, r in enumerate(rows, 1):
        r[0] = i
    return rows


def _normalize_severity(value: object) -> str:
    """Map vendor/engine severity labels to Critical / High / Medium / Low / Info."""
    s = str(value or "").split("\n")[0].strip()
    if not s:
        return "Info"
    low = s.lower().replace("_", " ")
    aliases = {
        "critical": "Critical", "crit": "Critical",
        "high": "High", "important": "High", "error": "High",
        "medium": "Medium", "moderate": "Medium", "med": "Medium", "warning": "Medium",
        "low": "Low", "minor": "Low",
        "info": "Info", "informational": "Info", "none": "Info", "unknown": "Info",
    }
    if low in aliases:
        return aliases[low]
    titled = s.title()
    if titled in SEVERITY_ORDER:
        return titled
    for key, norm in (
        ("critical", "Critical"), ("important", "High"), ("high", "High"),
        ("medium", "Medium"), ("moderate", "Medium"), ("low", "Low"), ("info", "Info"),
    ):
        if key in low:
            return norm
    return "Info"


def _apply_severity_colors(ws: Worksheet, start_row: int, count: int, severity_col: int = 3) -> None:
    """Force standard severity colors on severity column (overrides banding / leftover CF)."""
    for i in range(count):
        cell = ws.cell(start_row + i, severity_col)
        sev = _normalize_severity(cell.value)
        cell.value = sev
        fill = SEVERITY_FILL.get(sev)
        font = SEVERITY_FONT.get(sev)
        if fill is not None:
            cell.fill = fill
        if font is not None:
            cell.font = font
        cell.alignment = CENTER
        cell.border = THIN_BORDER


# ---------------------------------------------------------------------------
# Sheet fillers
# ---------------------------------------------------------------------------

def _fill_cover(ws: Worksheet, hostname: str, ip: str) -> None:
    """Place host identity BELOW the logo, with clean spacing for client-facing cover.

    Template layout (approx):
      rows 4–8  : Persian title (merged E4:I8)
      rows 10–15: logo image
      row  17+  : footer block (H17:M26)
    Identity lines go just under the logo, centered on the title/logo column band.
    """
    host = hostname or "—"
    ip_s = ip or "—"

    # Clear any previous identity writes in the logo/title band (do not touch footer H17+)
    for r in range(9, 17):
        for c in range(5, 10):
            cell = ws.cell(r, c)
            if type(cell).__name__ == "MergedCell":
                continue
            try:
                cell.value = None
            except AttributeError:
                pass

    # Spacer row under logo, then two identity lines (rows 16–17)
    # Row 16 may sit at logo bottom edge — use 16 as light spacer, content on 17–18
    # Footer occupies H17:M26; E17:G17 stay free for our text.
    def _write_identity(row: int, text: str, *, bold: bool, size: int, color: str) -> None:
        # Prefer a 5-column merge E:I when free; fall back to single cells
        try:
            for m in list(ws.merged_cells.ranges):
                if m.min_row == row and 5 <= m.min_col <= 7 and m.max_col <= 7:
                    try:
                        ws.unmerge_cells(str(m))
                    except Exception:
                        pass
            # E:G only — H17:M26 is the footer band; never overlap it
            ws.merge_cells(start_row=row, start_column=5, end_row=row, end_column=7)
        except Exception:
            pass
        cell = ws.cell(row, 5)
        if type(cell).__name__ == "MergedCell":
            return
        cell.value = text
        cell.font = Font(name="Calibri", size=size, bold=bold, color=color)
        cell.alignment = Alignment(horizontal="center", vertical="center")
        ws.row_dimensions[row].height = max(ws.row_dimensions[row].height or 18, 22)

    # Logo occupies rows ~10–15; footer text sits lower.
    # Place identity clearly UNDER the logo with breathing room (rows 20–21).
    # Use columns E–G only so we never collide with footer merge H17:M26.
    for r in range(16, 22):
        for c in range(5, 8):
            cell = ws.cell(r, c)
            if type(cell).__name__ != "MergedCell":
                try:
                    cell.value = None
                except AttributeError:
                    pass
    ws.row_dimensions[19].height = 18  # spacer under logo
    _write_identity(20, f"Hostname:  {host}", bold=True, size=14, color="1F4E78")
    _write_identity(21, f"IP Address:  {ip_s}", bold=False, size=13, color="2F5496")


def _fill_host_information(
    ws: Worksheet,
    inv,
    primary_ip: str,
    macs: list[str],
    listen: list[str],
    hostname: str,
    soc_agents: Optional[list[str]] = None,
    outbound: Optional[list[str]] = None,
) -> None:
    _clear_range(ws, 2, max(2, ws.max_row or 2), 8)
    inbound = ", ".join(listen[:80]) if listen else "—"
    outband = ", ".join((outbound or [])[:50]) if outbound else "—"
    values = [
        inv.os.pretty_name or f"{inv.os.family} {inv.os.version}".strip() or "—",
        inv.fqdn or hostname or "—",
        primary_ip or "—",
        ", ".join(macs[:6]) if macs else "—",
        inv.uname or inv.running_kernel or "—",
        ", ".join(soc_agents or [])[:120] if soc_agents else "Not detected",
        inbound,
        outband,
    ]
    for c, val in enumerate(values, 1):
        prefer_center = c in (2, 3, 4)
        _set_cell(ws, 2, c, val, border=True, prefer_center=prefer_center)
        try:
            cell = _resolve_writable_cell(ws, 2, c)
            if cell is not None:
                cell.alignment = Alignment(
                    horizontal="center" if prefer_center else "left",
                    vertical="center",
                    wrap_text=True,
                )
        except Exception:
            pass
    # taller row when many ports listed
    density = max(str(values[6]).count(","), str(values[7]).count(","), 1)
    ws.row_dimensions[2].height = max(36, min(120, 18 + 10 * density))


def _fill_firewall(
    ws: Worksheet,
    conns: list[dict],
    iptables: list[str],
    neighbors: list[dict],
    iface_map: Optional[dict[str, str]] = None,
) -> None:
    """Fill CM + Active Connections + IPTABLES + ARP without insert_rows."""
    iface_map = iface_map or {}
    # Template has many merged title rows; unmerge data area so writes never hit MergedCell
    try:
        _unmerge_area(ws, 2, max(ws.max_row or 2, 100), 1, 20)
    except Exception:
        pass

    resolve_iface = _iface_resolver(iface_map)
    local_ips = _local_ips_from_map(iface_map)

    cm_title = _find_row_by_title(ws, "Connection Matrix") or 1
    p1_title = _find_row_by_title(ws, "OS Firewall Rules (IPTABLES P1)", "IPTABLES P1")
    p2_title = _find_row_by_title(ws, "OS Firewall Rules (IPTABLES P2)", "IPTABLES P2")
    arp_title = _find_row_by_title(ws, "ARP")

    def _row_vals(r, cols=14):
        return [ws.cell(r, c).value for c in range(1, cols + 1)]

    p1_hdr = _row_vals(p1_title + 1, 6) if p1_title else [
        "Rule Type", "Chain/Rule Name", "Specification", "Security Comment", "Owner Comments", "Security Reviews"
    ]
    p2_hdr = _row_vals(p2_title + 1, 14) if p2_title else [
        "Chain", "Packets", "Bytes", "Target", "Protocol", "", "", "", "", "", "Extra", "", "", ""
    ]
    arp_hdr = _row_vals(arp_title + 1, 8) if arp_title else [
        "Interface", "Source Name", "Neighbor IP", "Destination MAC", "State", "", "", ""
    ]

    cm_header = cm_title + 1
    cm_data = cm_header + 1
    last = max(ws.max_row or cm_data, cm_data)
    _clear_range(ws, cm_data, last, 14)

    matrix_src = [c for c in conns if str(c.get("state", "")).upper() in ("LISTEN", "UNCONN")]
    if not matrix_src:
        matrix_src = conns[:40]
    cm_rows = []
    seen = set()
    for c in matrix_src:
        key = (c.get("protocol"), c.get("src_ip"), c.get("src_port"), c.get("state"))
        if key in seen:
            continue
        seen.add(key)
        if len(cm_rows) >= 80:
            break
        hint = _service_hint(str(c.get("src_port")), str(c.get("protocol")), str(c.get("state")))
        sip = str(c.get("src_ip", ""))
        iface = resolve_iface(sip)
        sec = _security_comment_conn(c, local_ips)
        cm_rows.append([
            "",  # VRF
            iface,
            hint or "",
            sip,
            c.get("src_port", ""),
            c.get("protocol", ""),
            "",  # destination name
            c.get("dst_ip", "") if str(c.get("dst_ip")) not in ("*", "0.0.0.0") else "",
            c.get("dst_port", "") if str(c.get("dst_port")) not in ("*",) else "",
            c.get("state", ""),
            hint or "",
            sec,
            "",
            "",
        ])
    _write_table_rows(ws, cm_data, cm_rows, 14, center_cols={5, 6, 9, 10})
    if cm_rows:
        _apply_band_rows(ws, cm_data, len(cm_rows), 14)
    _resize_table(ws, "Table5", cm_header, cm_data + max(len(cm_rows), 1) - 1, 1, 14)

    r = cm_data + max(len(cm_rows), 1) + 1
    _set_cell(ws, r, 1, "Active Connections", fill=PatternFill("solid", fgColor="4472C4"), font=Font(bold=True, color="FFFFFF"))
    _remerge_title(ws, r, 14)
    r += 1
    active_header = r
    headers_ac = [
        "Protocol", "Recv-Q", "Send-Q", "Source IP Address", "Source Port Number",
        "Destination IP Address", "Destination Port Number", "State", "User", "Inode",
        "Identified / Likely Service", "Security Comment", "Owner Comments", "Security Reviews",
    ]
    for c, h in enumerate(headers_ac, 1):
        _set_cell(ws, r, c, h, font=Font(bold=True), fill=PatternFill("solid", fgColor="D9E2F3"))
    r += 1
    active_data = r

    conn_rows = []
    for c in conns:
        if not c.get("src_ip") and not c.get("src_port"):
            continue
        if len(conn_rows) >= 500:
            break
        st = str(c.get("state", "")).upper()
        port_for_hint = str(c.get("src_port") if st in ("LISTEN", "UNCONN") else c.get("dst_port") or "")
        hint = _service_hint(port_for_hint, str(c.get("protocol")), st)
        comment = _security_comment_conn(c, local_ips)
        conn_rows.append([
            c.get("protocol", ""), c.get("recv_q", 0), c.get("send_q", 0),
            c.get("src_ip", ""), c.get("src_port", ""), c.get("dst_ip", ""), c.get("dst_port", ""),
            c.get("state", ""), c.get("user", ""), c.get("inode", ""),
            hint or "", comment, "", "",
        ])
    _write_table_rows(ws, active_data, conn_rows, 14, center_cols={1, 2, 3, 5, 7, 8})
    if conn_rows:
        _apply_band_rows(ws, active_data, len(conn_rows), 14)
    _resize_table(ws, "ActiveConnections", active_header, active_data + max(len(conn_rows), 1) - 1, 1, 14)
    r = active_data + max(len(conn_rows), 1) + 1

    useful_fw = []
    for ln in iptables:
        s = str(ln).strip()
        if not s or s.startswith(("CMD:", "RC=", "=====")):
            continue
        useful_fw.append(s)

    _set_cell(ws, r, 1, "OS Firewall Rules (IPTABLES P1)", fill=PatternFill("solid", fgColor="A9D08E"), font=Font(bold=True))
    _remerge_title(ws, r, 6)
    r += 1
    p1_header = r
    for c, h in enumerate(p1_hdr, 1):
        if h is None and c <= 5:
            h = ["Rule Type", "Chain/Rule Name", "Specification", "Security Comment", "Owner Comments"][c - 1]
        _set_cell(ws, r, c, h, font=Font(bold=True), fill=PatternFill("solid", fgColor="E2EFDA"))
    r += 1
    p1_data = r
    if useful_fw:
        p1_rows = []
        for ln in useful_fw[:200]:
            rule_type = "policy" if ln.startswith((":", "*", "Chain")) else "rule"
            name = ln.split()[0] if ln.split() else ""
            p1_rows.append([rule_type, name, ln[:500], "", "", ""])
    else:
        p1_rows = [[
            "info", "firewalld",
            "firewalld disabled/inactive; iptables rule dump not available under current privilege.",
            "Re-collect with root if host firewall rules must be evidenced.",
            "", "",
        ]]
    _write_table_rows(ws, p1_data, p1_rows, 6, center_cols={1})
    _apply_band_rows(ws, p1_data, len(p1_rows), 6, color_a="E2EFDA", color_b="FFFFFF")
    _resize_table(ws, "FirewallRulesP1", p1_header, p1_data + len(p1_rows) - 1, 1, 6)
    r = p1_data + len(p1_rows) + 1

    _set_cell(ws, r, 1, "OS Firewall Rules (IPTABLES P2)", fill=PatternFill("solid", fgColor="A9D08E"), font=Font(bold=True))
    _remerge_title(ws, r, 14)
    r += 1
    p2_header = r
    for c, h in enumerate(p2_hdr, 1):
        _set_cell(ws, r, c, h, font=Font(bold=True), fill=PatternFill("solid", fgColor="E2EFDA"))
    r += 1
    p2_data = r
    if useful_fw:
        p2_rows = [[""] * 10 + [ln[:500], "", "", ""] for ln in useful_fw[:200]]
    else:
        p2_rows = [[""] * 10 + ["No iptables -L/-S dump in collector evidence.", "", "", ""]]
    _write_table_rows(ws, p2_data, p2_rows, 14)
    _apply_band_rows(ws, p2_data, len(p2_rows), 14, color_a="E2EFDA", color_b="FFFFFF")
    _resize_table(ws, "FirewallRulesP2", p2_header, p2_data + len(p2_rows) - 1, 1, 14)
    r = p2_data + len(p2_rows) + 1

    _set_cell(ws, r, 1, "ARP", fill=PatternFill("solid", fgColor="5B9BD5"), font=Font(bold=True, color="FFFFFF"))
    _remerge_title(ws, r, 8)
    r += 1
    arp_header = r
    for c, h in enumerate(arp_hdr, 1):
        if h is None and c <= 5:
            h = ["Interface", "Source Name", "Neighbor IP", "Destination MAC", "State"][c - 1]
        _set_cell(ws, r, c, h, font=Font(bold=True), fill=PatternFill("solid", fgColor="DDEBF7"))
    r += 1
    arp_data = r
    arp_rows = []
    for n in neighbors[:250]:
        arp_rows.append([
            n.get("interface", ""), "", n.get("ip", ""), n.get("mac", ""), n.get("state", ""),
            "", "", "",
        ])
    if not arp_rows:
        arp_rows.append(["", "", "(no ARP/neighbor entries parsed)", "", "", "", "", ""])
    _write_table_rows(ws, arp_data, arp_rows, 8, center_cols={1, 3, 4, 5})
    _apply_band_rows(ws, arp_data, len(arp_rows), 8, color_a="DDEBF7", color_b="FFFFFF")
    _resize_table(ws, "ARPTable", arp_header, arp_data + len(arp_rows) - 1, 1, 8)



def _fill_simple_sheet(
    ws: Worksheet,
    rows: list[list[Any]],
    cols: int,
    *,
    center_cols: Optional[set[int]] = None,
) -> None:
    _clear_range(ws, 2, max(ws.max_row or 2, 2), cols)
    if rows:
        _write_table_rows(ws, 2, rows, cols, center_cols=center_cols or set())


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------

def write_full_assessment(
    result: AnalysisResult,
    output: str | Path,
    *,
    inventory_text: Optional[Path] = None,
    template: Optional[Path] = None,
) -> Path:
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if template is None:
        template = Path(__file__).resolve().parent / "assessment_template.xlsx"
    if not template.is_file():
        raise FileNotFoundError(f"assessment template missing: {template}")

    inv = result.inventory
    text = ""
    if inventory_text and Path(inventory_text).is_file():
        text = Path(inventory_text).read_text(encoding="utf-8", errors="replace")
        if text.startswith("\ufeff"):
            text = text[1:]

    hostname = inv.hostname or _meta(text, "HOSTNAME") or ""
    fqdn = inv.fqdn or _meta(text, "HOSTNAME_FULL") or hostname
    primary_ip = _meta(text, "PRIMARY_IP") or ""
    if not primary_ip:
        m = re.search(r"Primary IP\s*:\s*([0-9.]+)", text)
        if m:
            primary_ip = m.group(1)

    macs = parse_mac(text) if text else []
    conns = parse_connections(text) if text else []
    listen = _listen_ports(conns)
    routes = parse_routes(text) if text else []
    neighbors = parse_neighbors(text) if text else []
    iptables = parse_iptables(text) if text else []
    users = parse_users(text) if text else []
    groups = parse_groups(text) if text else []
    cron_jobs = parse_cron(text) if text else []
    root_procs = parse_root_procs(text) if text else []
    vuln_rows = _findings_to_template_rows(result)

    wb = load_workbook(str(template))

    if "Cover" in wb.sheetnames:
        _fill_cover(wb["Cover"], fqdn or hostname, primary_ip)

    if "Document Information" in wb.sheetnames:
        ws = wb["Document Information"]
        coll_date = _meta(text, "COLLECTION_DATE") or ""
        for r in range(1, min(ws.max_row or 1, 30) + 1):
            label = str(ws.cell(r, 1).value or "").strip().lower()
            if label in ("publish date", "date") and coll_date:
                _set_cell(ws, r, 2, coll_date, prefer_center=False)
            if label == "status":
                _set_cell(ws, r, 2, "Confidential", prefer_center=False)

    soc_agents = parse_soc_agents(text) if text else []
    iface_map = parse_iface_ip_map(text) if text else {}
    local_ips = _local_ips_from_map(iface_map)
    if primary_ip:
        local_ips.add(primary_ip)
    outbound = _outbound_summary(conns, local_ips) if conns else []

    if "Host information" in wb.sheetnames:
        _fill_host_information(
            wb["Host information"], inv, primary_ip, macs, listen, hostname,
            soc_agents=soc_agents, outbound=outbound,
        )

    if "Firewall Assessment" in wb.sheetnames:
        _fill_firewall(
            wb["Firewall Assessment"], conns, iptables, neighbors, iface_map=iface_map,
        )

    if "Package" in wb.sheetnames:
        pkg_rows = []
        for pkg in inv.packages:
            if pkg.package_manager in {"deb", "dpkg"}:
                pkg_rows.append([f"{pkg.name}|{pkg.installed_version}|{pkg.arch}", "", "", ""])
            else:
                ver = f"{pkg.version}-{pkg.release}" if pkg.release else pkg.version
                pkg_rows.append([f"{pkg.name}|{ver}|{pkg.arch}", "", "", ""])
        ws = wb["Package"]
        _fill_simple_sheet(ws, pkg_rows, 4, center_cols=set())
        if pkg_rows:
            _apply_band_rows(ws, 2, len(pkg_rows), 4, color_a="E9EEF5", color_b="FFFFFF")
            _resize_table(ws, "Table", 1, 1 + len(pkg_rows), 1, 4)

    if "Users" in wb.sheetnames:
        urows = []
        for u in users:
            sec = _security_comment_user(u)
            urows.append([
                hostname or primary_ip, u.get("username", ""), u.get("uid", ""), u.get("gid", ""),
                u.get("gecos", ""), u.get("shell", ""), u.get("home", ""),
                sec, "", "", "", "",
            ])
        _fill_simple_sheet(wb["Users"], urows, 12, center_cols={3, 4})
        if urows:
            _apply_band_rows(wb["Users"], 2, len(urows), 12)

    if "Groups" in wb.sheetnames:
        grows = [[hostname or primary_ip, g.get("name", ""), g.get("gid", ""), g.get("members", ""), "", "", ""] for g in groups]
        _fill_simple_sheet(wb["Groups"], grows, 7, center_cols={3})
        if grows:
            _apply_band_rows(wb["Groups"], 2, len(grows), 7)

    if "Routes" in wb.sheetnames:
        rrows = []
        for r in routes:
            sec = _security_comment_route(r)
            iface = r.get("interface") or ""
            if not iface and r.get("destination"):
                iface = _iface_resolver(iface_map)(str(r.get("gateway") or ""))
                if iface == "n/a":
                    iface = ""
            rrows.append([
                hostname or primary_ip, r.get("destination", ""), r.get("gateway", ""),
                iface, sec, "", "",
            ])
        _fill_simple_sheet(wb["Routes"], rrows, 7, center_cols={4})
        if rrows:
            _apply_band_rows(wb["Routes"], 2, len(rrows), 7)

    if "Processes Running by root" in wb.sheetnames:
        prows = []
        for p in root_procs:
            path = p.get("path", "")
            sec = _security_comment_process(path)
            prows.append([p.get("pid", ""), path, sec, "", ""])
        _fill_simple_sheet(wb["Processes Running by root"], prows, 5, center_cols={1})
        if prows:
            _apply_band_rows(wb["Processes Running by root"], 2, len(prows), 5)

    if "Cron Jobs" in wb.sheetnames:
        crows = []
        for job in cron_jobs:
            sec = security_comment_cron(job)
            crows.append([hostname or primary_ip, job, sec, "", ""])
        _fill_simple_sheet(wb["Cron Jobs"], crows, 5)
        if crows:
            _apply_band_rows(wb["Cron Jobs"], 2, len(crows), 5)

    if "Environment" in wb.sheetnames:
        env_rows_data = parse_environment(text) if text else []
        erows = [[e.get("user") or (hostname or primary_ip), e.get("env", ""), e.get("comment", "")] for e in env_rows_data]
        _fill_simple_sheet(wb["Environment"], erows, 3, center_cols=set())
        if erows:
            _apply_band_rows(wb["Environment"], 2, len(erows), 3)

    if "ssh known hosts" in wb.sheetnames:
        kh_rows = []
        for m in re.finditer(r"(?m)^KNOWN_HOST\|([^|]+)\|([^|]+)\|(.+)$", text):
            kh_rows.append([hostname or primary_ip, f"{m.group(1)}|{m.group(2)}|{m.group(3)}", "", "", ""])
        _fill_simple_sheet(wb["ssh known hosts"], kh_rows, 5)

    # Vulnerabilities — sorted + severity colors
    if "Vulnerabilities" in wb.sheetnames:
        ws = wb["Vulnerabilities"]
        # Remove template conditional formatting so severity colors stay correct
        try:
            ws.conditional_formatting._cf_rules.clear()
        except Exception:
            pass
        _clear_range(ws, 2, max(ws.max_row or 2, 2), 22)
        # Canonical order: Critical → High → Medium → Low → Info
        vuln_rows.sort(key=lambda r: SEVERITY_ORDER.get(_normalize_severity(r[2]), 9))
        for i, row in enumerate(vuln_rows, 1):
            row[0] = i
            row[2] = _normalize_severity(row[2])
        _write_table_rows(
            ws, 2, vuln_rows, 21,
            center_cols={1, 3},
        )
        _apply_band_rows(ws, 2, len(vuln_rows), 21, color_a="F7F7F7", color_b="FFFFFF")
        # Severity colors last — must override banding on column 3
        _apply_severity_colors(ws, 2, len(vuln_rows), severity_col=3)

    # Remediations — vendor advisory URL + concrete package update command
    if "Remediations" in wb.sheetnames:
        ws = wb["Remediations"]
        _clear_range(ws, 2, max(ws.max_row or 2, 2), 4)
        seen = set()
        rem_rows = []
        os_family = (inv.os.family if inv and inv.os else "redhat") or "redhat"
        os_version = (inv.os.version if inv and inv.os else "") or ""
        for row in vuln_rows:
            solution = str(row[5] or "").strip()
            advisory = str(row[9] or "").strip().split("\n")[0].strip()
            name = str(row[3] or "").strip()
            pkg = str(row[6] or "").strip().split("\n")[0].strip()
            fixed = str(row[8] or "").strip().split("\n")[0].strip()
            installed = str(row[7] or "").strip().split("\n")[0].strip()
            # Prefer structured remediation
            line = remediation_for_finding(
                package=pkg or name.split("—")[0].strip(),
                advisory=advisory,
                fixed_evr=fixed.split("=")[-1] if fixed else "",
                installed_evr=installed.split("=")[-1] if installed else "",
                solution=solution,
                os_family=str(os_family),
                os_version=str(os_version),
            )
            key = advisory or line
            if not key or key in seen:
                continue
            seen.add(key)
            url = vendor_advisory_url(advisory, str(os_family))
            rem_rows.append([line, url or "", "", ""])
        _write_table_rows(ws, 2, rem_rows, 4)
        if rem_rows:
            _apply_band_rows(ws, 2, len(rem_rows), 4, color_a="D6E3F0", color_b="FFFFFF")

    # Compliance — keep titles/styles, clear sample/benchmark data (not assessed yet)
    if "Compliance" in wb.sheetnames:
        ws = wb["Compliance"]
        try:
            # Preserve Persian notes (rows 1-5) and header row 8 / section titles
            # Clear summary count row 9 and CIS data rows from 18 onward
            _clear_range(ws, 9, min(15, ws.max_row or 9), 16)
            if (ws.max_row or 0) >= 18:
                _clear_range(ws, 18, ws.max_row, 16)
            # Soft note under header that compliance was not executed
            _set_cell(
                ws, 9, 1,
                "Compliance assessment not executed in this run — section reserved for future CIS/OpenSCAP results.",
                prefer_center=False,
            )
        except Exception:
            pass

    # Summary counts
    if "Summary" in wb.sheetnames:
        ws = wb["Summary"]
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for row in vuln_rows:
            sev = str(row[2] or "").split("\n")[0].strip().title()
            if sev in counts:
                counts[sev] += 1
        level = "Info"
        for s in ("Critical", "High", "Medium", "Low"):
            if counts[s] > 0:
                level = s
                break
        for r in range(1, min(ws.max_row or 1, 40) + 1):
            label = str(ws.cell(r, 1).value or "").strip()
            if label in counts:
                _set_cell(ws, r, 2, counts[label], prefer_center=True)
            if label == "Assessed Threat Level":
                _set_cell(ws, r, 2, level, prefer_center=True)
                if level in SEVERITY_FILL:
                    ws.cell(r, 2).fill = SEVERITY_FILL[level]
                    ws.cell(r, 2).font = SEVERITY_FONT[level]

    fd, temporary = tempfile.mkstemp(prefix=".offlineva-full-", suffix=".xlsx", dir=str(output.parent))
    os.close(fd)
    try:
        wb.save(temporary)
        os.replace(temporary, output)
    finally:
        wb.close()
        Path(temporary).unlink(missing_ok=True)
    return output
