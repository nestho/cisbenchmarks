from __future__ import annotations

"""Pure-Python Debian package version comparison.

The implementation follows the ordering rules used by dpkg: epoch first,
then upstream version, then Debian revision.  It intentionally does not use
SemVer or RPM comparison because both produce incorrect results for values
such as ``~rc1`` and ``+deb12u1``.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DebianVersion:
    epoch: int
    upstream: str
    revision: str


def split_version(value: str) -> DebianVersion:
    text = (value or "").strip()
    epoch_text = "0"
    remainder = text
    if ":" in remainder:
        candidate, remainder = remainder.split(":", 1)
        if not candidate.isdigit():
            raise ValueError(f"invalid Debian epoch in version: {value!r}")
        epoch_text = candidate
    if "-" in remainder:
        upstream, revision = remainder.rsplit("-", 1)
    else:
        upstream, revision = remainder, "0"
    if not upstream:
        raise ValueError(f"invalid empty Debian upstream version: {value!r}")
    return DebianVersion(int(epoch_text), upstream, revision or "0")


def _order(char: str) -> int:
    if char == "~":
        return -1
    if not char or char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _compare_part(left: str, right: str) -> int:
    li = ri = 0
    while li < len(left) or ri < len(right):
        while (
            (li < len(left) and not left[li].isdigit())
            or (ri < len(right) and not right[ri].isdigit())
        ):
            lc = left[li] if li < len(left) and not left[li].isdigit() else ""
            rc = right[ri] if ri < len(right) and not right[ri].isdigit() else ""
            difference = _order(lc) - _order(rc)
            if difference:
                return -1 if difference < 0 else 1
            if lc:
                li += 1
            if rc:
                ri += 1

        while li < len(left) and left[li] == "0":
            li += 1
        while ri < len(right) and right[ri] == "0":
            ri += 1

        lstart, rstart = li, ri
        while li < len(left) and left[li].isdigit():
            li += 1
        while ri < len(right) and right[ri].isdigit():
            ri += 1
        ldigits, rdigits = left[lstart:li], right[rstart:ri]
        if len(ldigits) != len(rdigits):
            return -1 if len(ldigits) < len(rdigits) else 1
        if ldigits != rdigits:
            return -1 if ldigits < rdigits else 1
    return 0


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0, or 1 using Debian/dpkg version semantics."""
    lver = split_version(left)
    rver = split_version(right)
    if lver.epoch != rver.epoch:
        return -1 if lver.epoch < rver.epoch else 1
    result = _compare_part(lver.upstream, rver.upstream)
    if result:
        return result
    return _compare_part(lver.revision, rver.revision)


def version_lt(left: str, right: str) -> bool:
    return compare_versions(left, right) < 0


def version_le(left: str, right: str) -> bool:
    return compare_versions(left, right) <= 0
