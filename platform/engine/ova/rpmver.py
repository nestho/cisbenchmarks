from __future__ import annotations

from functools import total_ordering


def _normalize_epoch(value: str | None) -> int:
    if value is None or str(value).strip().lower() in {"", "(none)", "none"}:
        return 0
    try:
        return int(str(value).strip())
    except ValueError:
        return 0


def split_evr(value: str) -> tuple[int, str, str]:
    value = (value or "").strip()
    epoch = 0
    if ":" in value:
        ep, value = value.split(":", 1)
        epoch = _normalize_epoch(ep)
    version, release = value, ""
    if "-" in value:
        version, release = value.rsplit("-", 1)
    return epoch, version, release


def _skip_separators(s: str, i: int) -> int:
    while i < len(s) and not s[i].isalnum() and s[i] not in "~^":
        i += 1
    return i


def rpmvercmp(a: str, b: str) -> int:
    """Pure-Python RPM-style version comparison including ~ and ^ semantics.

    Returns -1, 0, 1. This follows the public RPM algorithm closely enough for
    NEVRA comparison and is covered by regression tests in this project.
    """
    a = str(a or "")
    b = str(b or "")
    if a == b:
        return 0
    ia = ib = 0
    la, lb = len(a), len(b)

    while ia < la or ib < lb:
        ia = _skip_separators(a, ia)
        ib = _skip_separators(b, ib)

        # Tilde sorts before everything, even end-of-string.
        if (ia < la and a[ia] == "~") or (ib < lb and b[ib] == "~"):
            if not (ia < la and a[ia] == "~"):
                return 1
            if not (ib < lb and b[ib] == "~"):
                return -1
            ia += 1
            ib += 1
            continue

        # Caret is newer than base version but older than the next normal segment.
        if (ia < la and a[ia] == "^") or (ib < lb and b[ib] == "^"):
            if ia >= la:
                return -1
            if ib >= lb:
                return 1
            if not (ia < la and a[ia] == "^"):
                return 1
            if not (ib < lb and b[ib] == "^"):
                return -1
            ia += 1
            ib += 1
            continue

        if ia >= la or ib >= lb:
            break

        numeric = a[ia].isdigit()
        ja = ia
        while ja < la and a[ja].isalnum() and a[ja].isdigit() == numeric:
            ja += 1

        # Numeric segments always sort newer than alphabetic segments.
        if b[ib].isdigit() != numeric:
            return 1 if numeric else -1

        jb = ib
        while jb < lb and b[jb].isalnum() and b[jb].isdigit() == numeric:
            jb += 1

        sa, sb = a[ia:ja], b[ib:jb]
        if numeric:
            sa = sa.lstrip("0") or "0"
            sb = sb.lstrip("0") or "0"
            if len(sa) != len(sb):
                return 1 if len(sa) > len(sb) else -1
        if sa != sb:
            return 1 if sa > sb else -1
        ia, ib = ja, jb

    ia = _skip_separators(a, ia)
    ib = _skip_separators(b, ib)
    if ia >= la and ib >= lb:
        return 0
    if ia >= la:
        # Remaining ^ means the other side is a post-release snapshot.
        return -1 if ib < lb and b[ib] == "^" else -1
    if ib >= lb:
        return 1 if ia < la and a[ia] == "^" else 1
    return 0


def compare_evr(a: str, b: str) -> int:
    ea, va, ra = split_evr(a)
    eb, vb, rb = split_evr(b)
    if ea != eb:
        return 1 if ea > eb else -1
    result = rpmvercmp(va, vb)
    return result if result else rpmvercmp(ra, rb)


def satisfies(installed_evr: str, operation: str, expected_evr: str) -> bool | None:
    op = (operation or "equals").strip().lower().replace("_", " ")
    cmpv = compare_evr(installed_evr, expected_evr)
    mapping = {
        "equals": cmpv == 0,
        "equal": cmpv == 0,
        "not equal": cmpv != 0,
        "less than": cmpv < 0,
        "less than or equal": cmpv <= 0,
        "greater than": cmpv > 0,
        "greater than or equal": cmpv >= 0,
    }
    return mapping.get(op)


@total_ordering
class EVR:
    def __init__(self, value: str):
        self.value = value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, EVR) and compare_evr(self.value, other.value) == 0

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, EVR):
            return NotImplemented
        return compare_evr(self.value, other.value) < 0

    def __repr__(self) -> str:
        return f"EVR({self.value!r})"
