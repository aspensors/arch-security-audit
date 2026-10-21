import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from arch_security_audit.cli import main, demo_findings
from arch_security_audit.compare import compare_reports, load_report


def report():
    return {"schema_version": 1, "demo": True, "target": "fixture", "findings": [x.to_dict() for x in demo_findings()]}


class ComparisonTests(unittest.TestCase):
    def test_unchanged_ignores_metadata_and_order(self):
        before, after = report(), report()
        after.update(generated_at="later", tool_version="0.9", summary={})
        after["findings"].reverse()
        for item in after["findings"]:
            item["evidence"].reverse()
        self.assertTrue(all(x["change"] == "unchanged" for x in compare_reports(before, after)["changes"]))

    def test_status_change_keeps_both_findings(self):
        before, after = report(), report()
        after["findings"][1]["status"] = "UNKNOWN"
        item = next(x for x in compare_reports(before, after)["changes"] if x["check"] == "ssh")
        self.assertEqual((item["change"], item["before"]["status"], item["after"]["status"]), ("status_changed", "WARN", "UNKNOWN"))

    def test_evidence_and_description_change(self):
        for key, value in (("evidence", ["different chain"]), ("explanation", "new explanation")):
            after = report()
            after["findings"][0][key] = value
            self.assertEqual(compare_reports(report(), after)["changes"][0]["change"], "details_changed")

    def test_added_removed_are_not_fixes(self):
        before, after = report(), report()
        before["findings"] = before["findings"][:1]
        after["findings"] = after["findings"][1:2]
        self.assertEqual([x["change"] for x in compare_reports(before, after)["changes"]], ["removed", "added"])

    def test_mismatch_rejected(self):
        for key, value in (("demo", False), ("target", "other")):
            after = report()
            after[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                compare_reports(report(), after)

    def test_invalid_reports_rejected(self):
        variants = [None, [], {}, dict(report(), schema_version=True), dict(report(), findings=None)]
        for key, value in (("check", []), ("status", []), ("status", "SAFE"), ("evidence", [1]), ("title", None)):
            data = report()
            data["findings"][0][key] = value
            variants.append(data)
        duplicate = report()
        duplicate["findings"].append(copy.deepcopy(duplicate["findings"][0]))
        variants.append(duplicate)
        for data in variants:
            with self.subTest(data=data), self.assertRaises(ValueError):
                compare_reports(data, report())

    def test_files_limits_duplicate_keys_and_encoding(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            for raw in (b"{", b"\xff", b'{"schema_version":1,"schema_version":1}', b"[" * 2000):
                path.write_bytes(raw)
                with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                    load_report(path)
            path.write_text(json.dumps(report()))
            with patch("arch_security_audit.compare.MAX_BYTES", 10), self.assertRaises(ValueError):
                load_report(path)

    def test_offline_compare_on_non_linux_json_and_escaping(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text(json.dumps(report()))
            with patch("arch_security_audit.cli.sys.platform", "win32"), patch("arch_security_audit.cli.CHECKS", {}), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(["--compare", str(path), str(path), "--format", "json"]), 0)
            self.assertEqual(len(json.loads(output.getvalue())["changes"]), 5)
        after = report()
        after["findings"][0]["title"] = "evil\x1b[31m"
        with patch("arch_security_audit.cli.load_report", side_effect=[report(), after]), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["--compare", "a", "b"]), 0)
        self.assertNotIn("\x1b", output.getvalue())
        self.assertIn("\\x1b", output.getvalue())

    def test_cli_errors(self):
        with contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(main(["--compare", "/missing/before", "/missing/after"]), 2)
        self.assertIn("Cannot compare", error.getvalue())
        for flag in ("--strict", "--demo", "--online"):
            with self.subTest(flag=flag), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(["--compare", "a", "b", flag])
