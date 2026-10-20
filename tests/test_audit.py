import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arch_security_audit import checks
from arch_security_audit.cli import main, terminal_safe


class CheckTests(unittest.TestCase):
    def test_firewall_drop_policy_is_not_a_pass(self):
        data = {"nftables": [{"chain": {"family": "inet", "table": "filter", "name": "input",
                                       "hook": "input", "policy": "drop"}}]}
        result = checks.firewall(lambda _: checks.Command(0, json.dumps(data)))
        self.assertEqual(result.status, "INFO")
        self.assertIn("policy=drop", result.evidence[0])

    def test_firewall_forward_only_does_not_count_as_input(self):
        data = {"nftables": [{"chain": {"family": "inet", "hook": "forward"}}]}
        self.assertEqual(checks.firewall(lambda _: checks.Command(0, json.dumps(data))).status, "WARN")

    def test_firewall_permission_failure_is_unknown(self):
        result = checks.firewall(lambda _: checks.Command(1, error="Operation not permitted"))
        self.assertEqual(result.status, "UNKNOWN")

    def test_firewall_bad_json_is_unknown(self):
        for output in ("not json", '{"nftables": null}', '{"nftables":[{"chain":5}]}'):
            with self.subTest(output=output):
                self.assertEqual(checks.firewall(lambda _: checks.Command(0, output)).status, "UNKNOWN")

    def test_ssh_effective_output_and_mfa_caveat(self):
        output = "permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication yes\npubkeyauthentication yes\n"
        result = checks.ssh(lambda _: checks.Command(0, output))
        self.assertEqual(result.status, "WARN")
        self.assertIn("MFA", result.explanation)
        self.assertIn("Match", result.explanation)

    def test_ssh_restrictive_settings_are_not_full_pass(self):
        output = "permitrootlogin prohibit-password\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\n"
        self.assertEqual(checks.ssh(lambda _: checks.Command(0, output)).status, "INFO")

    def test_ssh_missing_output_is_unknown(self):
        self.assertEqual(checks.ssh(lambda _: checks.Command(0, "")).status, "UNKNOWN")

    def test_updates_default_never_runs_command(self):
        def forbidden(*args, **kwargs):
            self.fail("Offline mode invoked a command")
        self.assertEqual(checks.updates(runner=forbidden).status, "SKIP")

    @patch("arch_security_audit.checks.os.geteuid", return_value=1000)
    def test_checkupdates_exit_codes(self, _):
        for code, output, expected in ((2, "", "PASS"), (0, "linux 1 -> 2\n", "INFO"),
                                       (1, "", "UNKNOWN"), (0, "", "UNKNOWN"),
                                       (2, "linux 1 -> 2", "UNKNOWN")):
            with self.subTest(code=code, output=output):
                result = checks.updates(True, lambda *a, **k: checks.Command(code, output))
                self.assertEqual(result.status, expected)

    @patch("arch_security_audit.checks.os.geteuid", return_value=0)
    def test_online_as_root_is_skipped(self, _):
        self.assertEqual(checks.updates(True).status, "SKIP")

    def test_privilege_inventory_detects_extra_uid_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "etc").mkdir()
            (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\nother:x:0:0::/:/bin/sh\n")
            (root / "etc/group").write_text("wheel:x:998:alice\n")
            result = checks.privileges(root)
            self.assertEqual(result.status, "WARN")
            self.assertTrue(any("Additional UID 0" in line for line in result.evidence))

    def test_privileges_flags_world_writable_sudoers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "etc").mkdir()
            (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
            (root / "etc/group").write_text("")
            (root / "etc/sudoers").touch(mode=0o666)
            (root / "etc/sudoers").chmod(0o666)
            self.assertEqual(checks.privileges(root).status, "WARN")

    def test_privileges_incomplete_inventory_takes_priority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "etc").mkdir()
            (root / "etc/passwd").write_text("other:x:0:0::/:/bin/sh\n")
            result = checks.privileges(root)
            self.assertEqual(result.status, "UNKNOWN")
            self.assertTrue(any("Additional UID 0" in line for line in result.evidence))

    def test_suid_inventory_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "usr/bin").mkdir(parents=True)
            (root / "usr/local/bin").mkdir(parents=True)
            program = root / "usr/bin/example"
            program.write_text("fixture, never executed")
            program.chmod(0o4755)
            (root / "usr/bin/link").symlink_to(program)
            result = checks.suid(root)
            self.assertEqual(result.status, "INFO")
            self.assertEqual(len(result.evidence), 1)
            self.assertIn("/usr/bin/example", result.evidence[0])
            self.assertEqual(checks.suid(root, limit=0).status, "UNKNOWN")

    def test_suid_missing_paths_are_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(checks.suid(Path(tmp)).status, "UNKNOWN")

    def test_runner_missing_tool_and_timeout(self):
        with patch("arch_security_audit.checks.shutil.which", return_value=None):
            self.assertIsNone(checks.run(["nft"]).code)
        with patch("arch_security_audit.checks.shutil.which", return_value="/usr/bin/nft"), \
             patch("arch_security_audit.checks.subprocess.run", side_effect=checks.subprocess.TimeoutExpired("nft", 30)):
            self.assertIn("timed out", checks.run(["nft"]).error)

    def test_runner_ignores_user_path_and_does_not_use_shell(self):
        with patch("arch_security_audit.checks.shutil.which", return_value="/usr/bin/nft") as which, \
             patch("arch_security_audit.checks.subprocess.run", return_value=checks.subprocess.CompletedProcess([], 0, "", "")) as process:
            checks.run(["nft", "-j", "list", "ruleset"])
            self.assertEqual(which.call_args.kwargs["path"], "/usr/sbin:/usr/bin:/sbin:/bin")
            self.assertFalse(process.call_args.kwargs.get("shell", False))

    def test_demo_json_does_not_execute_live_checks(self):
        with patch.dict(checks.CHECKS, {name: lambda **kwargs: self.fail("Live check executed") for name in checks.CHECKS}):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["--demo", "--format", "json"])
            report = json.loads(output.getvalue())
            self.assertTrue(report["demo"])
            self.assertEqual(len(report["findings"]), 5)
            self.assertEqual(code, 0)

    def test_strict_exit_and_check_selection(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--demo", "--strict"]), 1)
            self.assertEqual(main(["--demo", "--only", "updates", "--strict"]), 0)
        with patch.dict(checks.CHECKS, {"ssh": lambda: checks.Finding("ssh", "UNKNOWN", "", [], "", "")}):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--only", "ssh", "--strict"]), 2)

    def test_terminal_escape_characters_are_escaped(self):
        self.assertEqual(terminal_safe("file\x1b[31m\n"), "file\\x1b[31m\\x0a")


if __name__ == "__main__":
    unittest.main()
