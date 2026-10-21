"""Offline comparison of schema-1 reports. No security ranking is inferred."""

import json
from pathlib import Path

STATUSES = {"PASS", "WARN", "INFO", "UNKNOWN", "SKIP"}
MAX_BYTES = 4 * 1024 * 1024


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def load_report(filename):
    with Path(filename).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Report exceeds the 4 MiB limit")
    try:
        report = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_keys)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("Report must be a bounded UTF-8 JSON object") from exc
    validate_report(report)
    return report


def validate_report(report):
    if not isinstance(report, dict) or type(report.get("schema_version")) is not int or report["schema_version"] != 1:
        raise ValueError("Expected audit report schema_version=1")
    if type(report.get("demo")) is not bool or not isinstance(report.get("target"), str):
        raise ValueError("Report needs demo (boolean) and target (string)")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("Report findings must be a list")
    seen = set()
    for item in findings:
        if not isinstance(item, dict):
            raise ValueError("Each finding must be an object")
        name = item.get("check")
        if not isinstance(name, str) or not name or name in seen:
            raise ValueError("Finding check identifiers must be unique nonempty strings")
        seen.add(name)
        if not isinstance(item.get("status"), str) or item["status"] not in STATUSES:
            raise ValueError(f"Invalid status for {name}")
        for key in ("title", "explanation", "suggestion"):
            if not isinstance(item.get(key), str):
                raise ValueError(f"Finding {name} needs string {key}")
        if not isinstance(item.get("evidence"), list) or not all(isinstance(x, str) for x in item["evidence"]):
            raise ValueError(f"Finding {name} needs a list of evidence strings")


def compare_reports(before, after):
    validate_report(before)
    validate_report(after)
    if (before["demo"], before["target"]) != (after["demo"], after["target"]):
        raise ValueError("Reports must have the same demo flag and target distribution")
    old = {item["check"]: item for item in before["findings"]}
    new = {item["check"]: item for item in after["findings"]}
    changes = []
    for name in sorted(old.keys() | new.keys()):
        left, right = old.get(name), new.get(name)
        if left is None:
            kind = "added"
        elif right is None:
            kind = "removed"
        elif left["status"] != right["status"]:
            kind = "status_changed"
        elif any(left[k] != right[k] for k in ("title", "explanation", "suggestion")) or set(left["evidence"]) != set(right["evidence"]):
            kind = "details_changed"
        else:
            kind = "unchanged"
        changes.append({"check": name, "change": kind, "before": left, "after": right})
    return {
        "comparison_schema_version": 1, "demo": after["demo"], "target": after["target"],
        "note": "A cleared warning is not proof of a fix. Removed checks were not assessed in the later report. Verify that both reports describe the same host.",
        "changes": changes,
    }
