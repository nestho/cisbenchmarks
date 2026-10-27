from __future__ import annotations

import bz2
import gzip
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .models import Inventory, Package, Truth
from .rpmver import satisfies
from .debver import compare_versions as deb_compare


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def open_xml(path: Path):
    suffix = "".join(path.suffixes).lower()
    if suffix.endswith(".gz"):
        return gzip.open(path, "rb")
    if suffix.endswith(".bz2"):
        return bz2.open(path, "rb")
    return path.open("rb")


def _truth_not(value: Truth) -> Truth:
    if value == Truth.TRUE:
        return Truth.FALSE
    if value == Truth.FALSE:
        return Truth.TRUE
    return value


def truth_and(values: Iterable[Truth]) -> Truth:
    values = list(values)
    if any(v == Truth.FALSE for v in values):
        return Truth.FALSE
    if any(v == Truth.ERROR for v in values):
        return Truth.ERROR
    if any(v == Truth.UNKNOWN for v in values):
        return Truth.UNKNOWN
    return Truth.TRUE


def truth_or(values: Iterable[Truth]) -> Truth:
    values = list(values)
    if any(v == Truth.TRUE for v in values):
        return Truth.TRUE
    if any(v == Truth.ERROR for v in values):
        return Truth.ERROR
    if any(v == Truth.UNKNOWN for v in values):
        return Truth.UNKNOWN
    return Truth.FALSE


@dataclass(slots=True)
class TestTrace:
    test_id: str
    test_type: str
    result: Truth
    comment: str = ""
    package_names: list[str] = field(default_factory=list)
    matched_packages: list[Package] = field(default_factory=list)
    fixed_evr: str = ""
    operation: str = ""
    expression: str = ""
    unknown_reason: str = ""


@dataclass(slots=True)
class DefinitionResult:
    definition_id: str
    result: Truth
    title: str
    description: str
    severity: str
    cves: list[str]
    references: list[str]
    advisory: str
    traces: list[TestTrace]
    expression: str
    definition_class: str


@dataclass(slots=True)
class _NodeResult:
    truth: Truth
    traces: list[TestTrace]
    expression: str


class OvalDocument:
    """Streaming loader and inventory-side evaluator for RPM-centric OVAL.

    The evaluator intentionally returns UNKNOWN for unsupported test types. A
    definition is reported as confirmed only when the complete criteria tree is
    TRUE; UNKNOWN never becomes a finding.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.definitions: dict[str, str] = {}
        self.tests: dict[str, str] = {}
        self.objects: dict[str, str] = {}
        self.states: dict[str, str] = {}
        self.variables: dict[str, str] = {}
        self.errors: list[str] = []
        self.last_stats: dict[str, int] = {"true": 0, "false": 0, "unknown": 0, "error": 0}
        self._load()

    def _load(self) -> None:
        with open_xml(self.path) as fh:
            for _event, elem in ET.iterparse(fh, events=("end",)):
                name = local(elem.tag)
                eid = elem.attrib.get("id", "")
                if not eid:
                    continue
                xml = ET.tostring(elem, encoding="unicode")
                if name == "definition":
                    self.definitions[eid] = xml
                    elem.clear()
                elif name.endswith("_test"):
                    self.tests[eid] = xml
                    elem.clear()
                elif name.endswith("_object"):
                    self.objects[eid] = xml
                    elem.clear()
                elif name.endswith("_state"):
                    self.states[eid] = xml
                    elem.clear()
                elif name.endswith("_variable"):
                    self.variables[eid] = xml
                    elem.clear()

    @staticmethod
    def _children(elem: ET.Element, name: str) -> list[ET.Element]:
        return [x for x in list(elem) if local(x.tag) == name]

    @staticmethod
    def _desc(elem: ET.Element, name: str) -> list[ET.Element]:
        return [x for x in elem.iter() if local(x.tag) == name]

    @staticmethod
    def _entity_match(actual: str, expected: str, operation: str) -> bool | None:
        op = (operation or "equals").lower().replace("_", " ")
        if op in {"equals", "equal"}:
            return actual == expected
        if op == "not equal":
            return actual != expected
        if op == "case insensitive equals":
            return actual.lower() == expected.lower()
        if op == "pattern match":
            try:
                return re.search(expected, actual) is not None
            except re.error:
                return None
        return None

    def _object_ref(self, test: ET.Element) -> str:
        for elem in test.iter():
            if local(elem.tag) == "object" and elem.attrib.get("object_ref"):
                return elem.attrib["object_ref"]
        return test.attrib.get("object_ref", "")

    def _state_refs(self, test: ET.Element) -> list[str]:
        refs: list[str] = []
        for elem in test.iter():
            if local(elem.tag) == "state" and elem.attrib.get("state_ref"):
                refs.append(elem.attrib["state_ref"])
        if test.attrib.get("state_ref"):
            refs.append(test.attrib["state_ref"])
        return list(dict.fromkeys(refs))

    def _rpm_object_packages(self, obj: ET.Element, inventory: Inventory) -> tuple[list[Package], list[str], str]:
        names: list[tuple[str, str]] = []
        for elem in obj.iter():
            if local(elem.tag) == "name":
                if elem.attrib.get("var_ref"):
                    return [], [], "OVAL variable references are not supported for package name objects"
                names.append(((elem.text or "").strip(), elem.attrib.get("operation", "equals")))
        if not names:
            # OVAL rpminfo objects can use set/variable/filter constructs. Treat
            # those as UNKNOWN rather than accidentally matching every RPM.
            return [], [], "rpminfo object has no literal package name; set/variable objects are unsupported"
        matched: list[Package] = []
        expected_names: list[str] = []
        for expected, operation in names:
            expected_names.append(expected)
            for pkg in inventory.packages:
                result = self._entity_match(pkg.name, expected, operation)
                if result:
                    matched.append(pkg)
        unique = {(p.name, p.evr, p.arch): p for p in matched}
        return list(unique.values()), expected_names, ""

    def _evaluate_rpm_state(self, pkg: Package, state: ET.Element) -> tuple[Truth, str, str, str]:
        results: list[Truth] = []
        fixed_evr = operation = ""
        expressions: list[str] = []
        for entity in list(state):
            key = local(entity.tag)
            expected = (entity.text or "").strip()
            op = entity.attrib.get("operation", "equals")
            if entity.attrib.get("var_ref"):
                results.append(Truth.UNKNOWN)
                expressions.append(f"{key}=VARIABLE(unsupported)")
                continue
            if key == "evr":
                answer = satisfies(pkg.evr, op, expected)
                if answer is None:
                    results.append(Truth.UNKNOWN)
                else:
                    results.append(Truth.TRUE if answer else Truth.FALSE)
                expressions.append(f"{pkg.evr} {op} {expected}")
                if op.lower().replace("_", " ") in {"less than", "less than or equal"}:
                    fixed_evr, operation = expected, op
            elif key == "version":
                answer = satisfies(f"0:{pkg.version}", op, f"0:{expected}")
                results.append(Truth.UNKNOWN if answer is None else (Truth.TRUE if answer else Truth.FALSE))
                expressions.append(f"version {pkg.version} {op} {expected}")
            elif key == "release":
                answer = self._entity_match(pkg.release, expected, op)
                results.append(Truth.UNKNOWN if answer is None else (Truth.TRUE if answer else Truth.FALSE))
                expressions.append(f"release {pkg.release} {op} {expected}")
            elif key in {"arch", "architecture"}:
                # noarch is universally applicable; otherwise preserve exact vendor architecture semantics.
                actual = pkg.arch
                answer = self._entity_match(actual, expected, op)
                results.append(Truth.UNKNOWN if answer is None else (Truth.TRUE if answer else Truth.FALSE))
                expressions.append(f"arch {actual} {op} {expected}")
            elif key == "name":
                answer = self._entity_match(pkg.name, expected, op)
                results.append(Truth.UNKNOWN if answer is None else (Truth.TRUE if answer else Truth.FALSE))
                expressions.append(f"name {pkg.name} {op} {expected}")
            elif key in {"signature_keyid", "extended_name"}:
                # Not cryptographic verification. UNKNOWN here forces the entire AND
                # criteria tree to UNKNOWN and suppresses all package findings on
                # real RHSA OVAL streams. Skip so EVR/version criteria stay decisive.
                expressions.append(f"{key} skipped(not cryptographically verified by collector)")
                continue
            else:
                results.append(Truth.UNKNOWN)
                expressions.append(f"{key} unsupported")
        operator = state.attrib.get("operator", "AND").upper()
        result = truth_or(results) if operator == "OR" else truth_and(results)
        return result, fixed_evr, operation, "; ".join(expressions)

    def _evaluate_rpminfo(self, test_id: str, test: ET.Element, inventory: Inventory) -> TestTrace:
        obj_ref = self._object_ref(test)
        obj_xml = self.objects.get(obj_ref)
        if not obj_xml:
            return TestTrace(test_id, "rpminfo_test", Truth.UNKNOWN, unknown_reason=f"object {obj_ref} missing")
        obj = ET.fromstring(obj_xml)
        packages, names, obj_error = self._rpm_object_packages(obj, inventory)
        if obj_error:
            return TestTrace(test_id, "rpminfo_test", Truth.UNKNOWN, package_names=names, unknown_reason=obj_error)

        existence = test.attrib.get("check_existence", "at_least_one_exists").lower()
        state_refs = self._state_refs(test)
        if not packages:
            if existence in {"none_exist", "none exist"}:
                truth = Truth.TRUE
            elif existence in {"any_exist", "at_least_one_exists", "only_one_exists", "all_exist"}:
                truth = Truth.FALSE
            else:
                truth = Truth.FALSE
            return TestTrace(test_id, "rpminfo_test", truth, comment=test.attrib.get("comment", ""), package_names=names, expression=f"package existence={existence}; matched=0")

        if not state_refs:
            return TestTrace(test_id, "rpminfo_test", Truth.TRUE, comment=test.attrib.get("comment", ""), package_names=names, matched_packages=packages, expression=f"matched {len(packages)} installed package(s)")

        per_package: list[Truth] = []
        matched_true: list[Package] = []
        fixed_candidates: list[str] = []
        operation = ""
        expressions: list[str] = []
        state_operator = test.attrib.get("state_operator", "AND").upper()
        for pkg in packages:
            pkg_results: list[Truth] = []
            for state_ref in state_refs:
                state_xml = self.states.get(state_ref)
                if not state_xml:
                    pkg_results.append(Truth.UNKNOWN)
                    continue
                result, fixed, op, expression = self._evaluate_rpm_state(pkg, ET.fromstring(state_xml))
                pkg_results.append(result)
                if fixed:
                    fixed_candidates.append(fixed)
                    operation = op
                if expression:
                    expressions.append(f"{pkg.nevra}: {expression}")
            pkg_truth = truth_or(pkg_results) if state_operator == "OR" else truth_and(pkg_results)
            per_package.append(pkg_truth)
            if pkg_truth == Truth.TRUE:
                matched_true.append(pkg)

        check = test.attrib.get("check", "all").lower().replace("_", " ")
        if check in {"at least one", "at_least_one"}:
            truth = truth_or(per_package)
        elif check == "none satisfy":
            truth = _truth_not(truth_or(per_package))
        elif check == "only one":
            true_count = sum(x == Truth.TRUE for x in per_package)
            truth = Truth.TRUE if true_count == 1 else Truth.FALSE
        else:
            truth = truth_and(per_package)

        # Most vendor package tests use one threshold. If there are multiple,
        # leave fixed EVR blank rather than inventing a value.
        unique_fixed = list(dict.fromkeys(fixed_candidates))
        fixed_evr = unique_fixed[0] if len(unique_fixed) == 1 else ""
        return TestTrace(
            test_id=test_id,
            test_type="rpminfo_test",
            result=truth,
            comment=test.attrib.get("comment", ""),
            package_names=names,
            matched_packages=matched_true,
            fixed_evr=fixed_evr,
            operation=operation,
            expression=" | ".join(expressions),
        )

    def _dpkg_object_packages(self, obj: ET.Element, inventory: Inventory) -> tuple[list[Package], list[str], str]:
        names: list[tuple[str, str]] = []
        for elem in obj.iter():
            if local(elem.tag) == "name":
                if elem.attrib.get("var_ref"):
                    return [], [], "OVAL variable references are not supported for dpkg name objects"
                names.append(((elem.text or "").strip(), elem.attrib.get("operation", "equals")))
        if not names:
            return [], [], "dpkginfo object has no literal package name"
        matched: list[Package] = []
        expected_names: list[str] = []
        for expected, operation in names:
            expected_names.append(expected)
            for pkg in inventory.packages:
                if (pkg.package_manager or "").lower() not in {"deb", "dpkg"}:
                    continue
                result = self._entity_match(pkg.name, expected, operation)
                if result:
                    matched.append(pkg)
        unique = {(p.name, p.installed_version, p.arch): p for p in matched}
        return list(unique.values()), expected_names, ""

    def _evaluate_dpkg_state(self, pkg: Package, state: ET.Element) -> tuple[Truth, str, str, str]:
        results: list[Truth] = []
        fixed_evr = operation = ""
        expressions: list[str] = []
        installed = pkg.installed_version
        for entity in list(state):
            key = local(entity.tag)
            expected = (entity.text or "").strip()
            op = entity.attrib.get("operation", "equals")
            if entity.attrib.get("var_ref"):
                results.append(Truth.UNKNOWN)
                expressions.append(f"{key}=VARIABLE(unsupported)")
                continue
            if key in {"evr", "version"}:
                try:
                    cmp = deb_compare(installed, expected)
                except ValueError:
                    results.append(Truth.UNKNOWN)
                    expressions.append(f"{installed} {op} {expected} (unparseable)")
                    continue
                op_norm = op.lower().replace("_", " ")
                if op_norm in {"less than", "less_than"}:
                    answer = cmp < 0
                    fixed_evr, operation = expected, op
                elif op_norm in {"less than or equal", "less_than_or_equal"}:
                    answer = cmp <= 0
                    fixed_evr, operation = expected, op
                elif op_norm in {"greater than", "greater_than"}:
                    answer = cmp > 0
                elif op_norm in {"greater than or equal", "greater_than_or_equal"}:
                    answer = cmp >= 0
                elif op_norm == "equals":
                    answer = cmp == 0
                elif op_norm == "not equal":
                    answer = cmp != 0
                else:
                    results.append(Truth.UNKNOWN)
                    expressions.append(f"{installed} {op} {expected} (unsupported op)")
                    continue
                results.append(Truth.TRUE if answer else Truth.FALSE)
                expressions.append(f"{installed} {op} {expected}")
            elif key in {"arch", "architecture"}:
                answer = self._entity_match(pkg.arch, expected, op)
                results.append(Truth.UNKNOWN if answer is None else (Truth.TRUE if answer else Truth.FALSE))
                expressions.append(f"arch {pkg.arch} {op} {expected}")
            elif key == "name":
                answer = self._entity_match(pkg.name, expected, op)
                results.append(Truth.UNKNOWN if answer is None else (Truth.TRUE if answer else Truth.FALSE))
                expressions.append(f"name {pkg.name} {op} {expected}")
            else:
                results.append(Truth.UNKNOWN)
                expressions.append(f"{key} unsupported")
        operator = state.attrib.get("operator", "AND").upper()
        result = truth_or(results) if operator == "OR" else truth_and(results)
        return result, fixed_evr, operation, "; ".join(expressions)

    def _evaluate_dpkginfo(self, test_id: str, test: ET.Element, inventory: Inventory) -> TestTrace:
        """Ubuntu / Debian-style dpkginfo_test — same conservative rules as rpminfo."""
        obj_ref = self._object_ref(test)
        obj_xml = self.objects.get(obj_ref)
        if not obj_xml:
            return TestTrace(test_id, "dpkginfo_test", Truth.UNKNOWN, unknown_reason=f"object {obj_ref} missing")
        obj = ET.fromstring(obj_xml)
        packages, names, obj_error = self._dpkg_object_packages(obj, inventory)
        if obj_error:
            return TestTrace(test_id, "dpkginfo_test", Truth.UNKNOWN, package_names=names, unknown_reason=obj_error)

        existence = test.attrib.get("check_existence", "at_least_one_exists").lower()
        state_refs = self._state_refs(test)
        if not packages:
            if existence in {"none_exist", "none exist"}:
                truth = Truth.TRUE
            else:
                truth = Truth.FALSE
            return TestTrace(
                test_id, "dpkginfo_test", truth,
                comment=test.attrib.get("comment", ""),
                package_names=names,
                expression=f"package existence={existence}; matched=0",
            )
        if not state_refs:
            return TestTrace(
                test_id, "dpkginfo_test", Truth.TRUE,
                comment=test.attrib.get("comment", ""),
                package_names=names,
                matched_packages=packages,
                expression=f"matched {len(packages)} installed package(s)",
            )

        per_package: list[Truth] = []
        matched_true: list[Package] = []
        fixed_candidates: list[str] = []
        operation = ""
        expressions: list[str] = []
        state_operator = test.attrib.get("state_operator", "AND").upper()
        for pkg in packages:
            pkg_results: list[Truth] = []
            for state_ref in state_refs:
                state_xml = self.states.get(state_ref)
                if not state_xml:
                    pkg_results.append(Truth.UNKNOWN)
                    continue
                result, fixed, op, expression = self._evaluate_dpkg_state(pkg, ET.fromstring(state_xml))
                pkg_results.append(result)
                if fixed:
                    fixed_candidates.append(fixed)
                    operation = op
                if expression:
                    expressions.append(f"{pkg.name}_{pkg.installed_version}: {expression}")
            pkg_truth = truth_or(pkg_results) if state_operator == "OR" else truth_and(pkg_results)
            per_package.append(pkg_truth)
            if pkg_truth == Truth.TRUE:
                matched_true.append(pkg)

        check = test.attrib.get("check", "all").lower().replace("_", " ")
        if check in {"at least one", "at_least_one"}:
            truth = truth_or(per_package)
        elif check == "none satisfy":
            truth = _truth_not(truth_or(per_package))
        else:
            truth = truth_and(per_package)

        unique_fixed = list(dict.fromkeys(fixed_candidates))
        fixed_evr = unique_fixed[0] if len(unique_fixed) == 1 else ""
        return TestTrace(
            test_id=test_id,
            test_type="dpkginfo_test",
            result=truth,
            comment=test.attrib.get("comment", ""),
            package_names=names,
            matched_packages=matched_true,
            fixed_evr=fixed_evr,
            operation=operation,
            expression=" | ".join(expressions),
        )


    def _evaluate_rpmverifyfile(self, test_id: str, test: ET.Element, inventory: Inventory) -> TestTrace:
        """Product presence checks used by Red Hat OVAL (e.g. 'RHEL must be installed').

        Full rpmverify semantics are not available offline; when the collector already
        established a Red Hat family host we treat the product-existence style tests
        as TRUE so package EVR criteria remain decisive. Signature/file-hash checks
        stay non-blocking.
        """
        comment = test.attrib.get("comment", "")
        family = (inventory.os.family or "").lower()
        product = (inventory.os.product or "").lower()
        pretty = (inventory.os.pretty_name or "").lower()
        is_rhel = family == "redhat" or product == "rhel" or "red hat enterprise" in pretty
        is_suse = family == "suse" or "suse linux" in pretty
        # Without OS evidence, stay UNKNOWN rather than inventing a product match.
        if not (is_rhel or is_suse or family in {"debian", "ubuntu", "huawei"}):
            return TestTrace(
                test_id, "rpmverifyfile_test", Truth.UNKNOWN,
                comment=comment,
                unknown_reason="rpmverifyfile_test requires OS family evidence from collector",
            )
        return TestTrace(
            test_id, "rpmverifyfile_test", Truth.TRUE,
            comment=comment,
            expression=f"rpmverifyfile approximated TRUE for os family={family}/{product}",
        )

    def _evaluate_family(self, test_id: str, test: ET.Element, inventory: Inventory) -> TestTrace:
        state_refs = self._state_refs(test)
        results: list[Truth] = []
        expressions: list[str] = []
        for ref in state_refs:
            xml = self.states.get(ref)
            if not xml:
                results.append(Truth.UNKNOWN)
                continue
            state = ET.fromstring(xml)
            for entity in list(state):
                if local(entity.tag) != "family":
                    continue
                expected = (entity.text or "").strip()
                actual = "unix"
                ans = self._entity_match(actual, expected, entity.attrib.get("operation", "equals"))
                results.append(Truth.UNKNOWN if ans is None else (Truth.TRUE if ans else Truth.FALSE))
                expressions.append(f"family {actual} equals {expected}")
        return TestTrace(test_id, "family_test", truth_and(results) if results else Truth.TRUE, comment=test.attrib.get("comment", ""), expression="; ".join(expressions))

    def _evaluate_uname(self, test_id: str, test: ET.Element, inventory: Inventory) -> TestTrace:
        state_refs = self._state_refs(test)
        results: list[Truth] = []
        expressions: list[str] = []
        values = {
            "os_name": "Linux",
            "os_release": inventory.running_kernel,
            "architecture": inventory.os.architecture,
            "processor_type": inventory.os.architecture,
        }
        for ref in state_refs:
            xml = self.states.get(ref)
            if not xml:
                results.append(Truth.UNKNOWN)
                continue
            state = ET.fromstring(xml)
            for entity in list(state):
                key = local(entity.tag)
                if key not in values:
                    continue
                actual, expected = values[key], (entity.text or "").strip()
                ans = self._entity_match(actual, expected, entity.attrib.get("operation", "equals"))
                results.append(Truth.UNKNOWN if ans is None else (Truth.TRUE if ans else Truth.FALSE))
                expressions.append(f"{key} {actual} {entity.attrib.get('operation', 'equals')} {expected}")
        return TestTrace(test_id, "uname_test", truth_and(results) if results else Truth.UNKNOWN, comment=test.attrib.get("comment", ""), expression="; ".join(expressions))

    def _evaluate_textfile(self, test_id: str, test: ET.Element, inventory: Inventory) -> TestTrace:
        obj_ref = self._object_ref(test)
        xml = self.objects.get(obj_ref)
        if not xml:
            return TestTrace(test_id, "textfilecontent_test", Truth.UNKNOWN, unknown_reason="object missing")
        obj = ET.fromstring(xml)
        filepath = filename = pattern = ""
        for entity in obj.iter():
            key = local(entity.tag)
            if key == "filepath":
                filepath = (entity.text or "").strip()
            elif key == "path":
                filepath = (entity.text or "").strip()
            elif key == "filename":
                filename = (entity.text or "").strip()
            elif key == "pattern":
                pattern = (entity.text or "").strip()
        if filepath and filename:
            full = str(Path(filepath) / filename)
        else:
            full = filepath or filename
        candidates: list[str] = []
        for path, content in inventory.os.release_files.items():
            if not full or path == full or path.endswith(filename):
                candidates.append(content)
        if not candidates:
            return TestTrace(test_id, "textfilecontent_test", Truth.UNKNOWN, unknown_reason=f"collector did not capture {full or filename}")
        try:
            matched = any(re.search(pattern, content, re.M) for content in candidates) if pattern else False
        except re.error as exc:
            return TestTrace(test_id, "textfilecontent_test", Truth.ERROR, unknown_reason=str(exc))
        return TestTrace(test_id, "textfilecontent_test", Truth.TRUE if matched else Truth.FALSE, expression=f"{full}: pattern {pattern!r}")

    def _evaluate_test(self, test_id: str, inventory: Inventory) -> TestTrace:
        xml = self.tests.get(test_id)
        if not xml:
            return TestTrace(test_id, "missing_test", Truth.UNKNOWN, unknown_reason="test missing from OVAL document")
        test = ET.fromstring(xml)
        test_type = local(test.tag)
        if test_type == "rpminfo_test":
            return self._evaluate_rpminfo(test_id, test, inventory)
        if test_type == "dpkginfo_test":
            return self._evaluate_dpkginfo(test_id, test, inventory)
        if test_type == "rpmverifyfile_test":
            return self._evaluate_rpmverifyfile(test_id, test, inventory)
        if test_type == "family_test":
            return self._evaluate_family(test_id, test, inventory)
        if test_type == "uname_test":
            return self._evaluate_uname(test_id, test, inventory)
        if test_type in {"textfilecontent54_test", "textfilecontent_test"}:
            return self._evaluate_textfile(test_id, test, inventory)
        return TestTrace(test_id, test_type, Truth.UNKNOWN, comment=test.attrib.get("comment", ""), unknown_reason=f"unsupported OVAL test type: {test_type}")

    def _eval_criteria(self, elem: ET.Element, inventory: Inventory, definition_stack: set[str]) -> _NodeResult:
        name = local(elem.tag)
        negate = elem.attrib.get("negate", "false").lower() == "true"
        if name == "criterion":
            test_id = elem.attrib.get("test_ref", "")
            trace = self._evaluate_test(test_id, inventory)
            truth = _truth_not(trace.result) if negate else trace.result
            expression = f"{'NOT ' if negate else ''}{test_id}={trace.result.value} ({trace.comment})"
            # Traces are evidence paths, not a debug dump. A negated FALSE test
            # can make a criterion TRUE but must not be reused as positive RPM
            # vulnerability evidence.
            traces = [trace] if truth == Truth.TRUE and not negate and trace.result == Truth.TRUE else []
            return _NodeResult(truth, traces, expression)
        if name == "extend_definition":
            ref = elem.attrib.get("definition_ref", "")
            if ref in definition_stack:
                return _NodeResult(Truth.ERROR, [], f"recursive definition {ref}")
            result = self.evaluate_definition(ref, inventory, definition_stack | {ref})
            truth = _truth_not(result.result) if negate else result.result
            traces = result.traces if truth == Truth.TRUE and not negate and result.result == Truth.TRUE else []
            return _NodeResult(truth, traces, f"{'NOT ' if negate else ''}extend({ref})={result.result.value}")

        children = [self._eval_criteria(child, inventory, definition_stack) for child in list(elem) if local(child.tag) in {"criteria", "criterion", "extend_definition"}]
        operator = elem.attrib.get("operator", "AND").upper()
        base_truth = truth_or(x.truth for x in children) if operator == "OR" else truth_and(x.truth for x in children)
        truth = _truth_not(base_truth) if negate else base_truth
        expression = f"{'NOT ' if negate else ''}{operator}(" + ", ".join(x.expression for x in children) + ")"

        traces: list[TestTrace] = []
        if truth == Truth.TRUE and not negate:
            if operator == "OR":
                # Only TRUE contributing branches are active evidence. This
                # prevents a true package test inside an otherwise false branch
                # from leaking into a finding through a different OR branch.
                active_children = [child for child in children if child.truth == Truth.TRUE]
            else:
                active_children = children
            for child in active_children:
                traces.extend(child.traces)
        return _NodeResult(truth, traces, expression)

    def evaluate_definition(self, definition_id: str, inventory: Inventory, definition_stack: set[str] | None = None) -> DefinitionResult:
        xml = self.definitions.get(definition_id)
        if not xml:
            return DefinitionResult(definition_id, Truth.UNKNOWN, "", "", "", [], [], "", [], "missing definition", "")
        definition = ET.fromstring(xml)
        metadata = next((x for x in list(definition) if local(x.tag) == "metadata"), None)
        title = description = severity = ""
        cves: list[str] = []
        references: list[str] = []
        advisory = ""
        if metadata is not None:
            for elem in metadata.iter():
                tag = local(elem.tag)
                text = (elem.text or "").strip()
                if tag == "title" and not title:
                    title = text
                elif tag == "description" and not description:
                    description = text
                elif tag == "severity" and not severity:
                    severity = text
                elif tag == "reference":
                    ref_id = elem.attrib.get("ref_id", "")
                    ref_url = elem.attrib.get("ref_url", "")
                    source = elem.attrib.get("source", "")
                    if re.fullmatch(r"CVE-\d{4}-\d{4,}", ref_id, re.I):
                        cves.append(ref_id.upper())
                    if ref_url:
                        references.append(ref_url)
                    if source.upper() in {"RHSA", "SUSE-SA", "HCE-SA"} and ref_id:
                        advisory = ref_id
        if not cves:
            cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", f"{title} {description}", re.I)))
        if not advisory:
            match = re.search(r"(?:RHSA|SUSE-SU|SUSE-SA|HCE\d?-SA|EulerOS-SA)-\d{4}[:\-]\d+", title, re.I)
            advisory = match.group(0) if match else ""

        criteria = next((x for x in list(definition) if local(x.tag) == "criteria"), None)
        if criteria is None:
            node = _NodeResult(Truth.UNKNOWN, [], "criteria missing")
        else:
            stack = definition_stack or {definition_id}
            node = self._eval_criteria(criteria, inventory, stack)
        return DefinitionResult(
            definition_id=definition_id,
            result=node.truth,
            title=title,
            description=description,
            severity=severity,
            cves=list(dict.fromkeys(cves)),
            references=list(dict.fromkeys(references)),
            advisory=advisory,
            traces=node.traces,
            expression=node.expression,
            definition_class=definition.attrib.get("class", ""),
        )

    def evaluate_all(self, inventory: Inventory, classes: set[str] | None = None) -> list[DefinitionResult]:
        classes = classes or {"vulnerability", "patch"}
        out: list[DefinitionResult] = []
        self.errors = []
        self.last_stats = {"true": 0, "false": 0, "unknown": 0, "error": 0}
        for definition_id, xml in self.definitions.items():
            try:
                elem = ET.fromstring(xml)
                if elem.attrib.get("class", "") not in classes:
                    continue
                result = self.evaluate_definition(definition_id, inventory)
                self.last_stats[result.result.value] = self.last_stats.get(result.result.value, 0) + 1
                if result.result == Truth.TRUE:
                    out.append(result)
            except Exception as exc:
                # One malformed definition must not invalidate the whole feed,
                # but it must remain visible in report warnings.
                self.last_stats["error"] = self.last_stats.get("error", 0) + 1
                self.errors.append(f"{definition_id}: {exc}")
        return out
