"""Incomplete account/configuration data must not look like a complete inventory."""
from pathlib import Path
import tempfile
import unittest
from arch_security_audit import checks


class IncompleteInputTests(unittest.TestCase):
    def test_malformed_group_records_are_unknown(self):
        for group in ("wheel:x:not-a-gid\n", "wheel:x:bad:alice\n", ":x:10:alice\n"):
            with self.subTest(group=group), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "etc").mkdir()
                (root / "etc/passwd").write_text("root:x:0:0::/:/bin/sh\n")
                (root / "etc/group").write_text(group)
                finding = checks.privileges(root)
                self.assertEqual(finding.status, "UNKNOWN")
                self.assertIn("Malformed /etc/group entry", finding.evidence)
                self.assertIn("Local UID 0 account: root", finding.evidence)

    def test_invalid_passwd_group_id_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "etc").mkdir()
            (root / "etc/passwd").write_text("root:x:0:bad::/:/bin/sh\n")
            (root / "etc/group").write_text("wheel:x:10:alice\n")
            result = checks.privileges(root)
            self.assertEqual(result.status, "UNKNOWN")
            self.assertIn("wheel supplementary members: alice", result.evidence)

    def test_unreadable_account_encoding_keeps_other_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "etc").mkdir()
            (root / "etc/passwd").write_bytes(b"\xff")
            (root / "etc/group").write_text("wheel:x:10:alice\n")
            result = checks.privileges(root)
            self.assertEqual(result.status, "UNKNOWN")
            self.assertIn("wheel supplementary members: alice", result.evidence)

    def test_blank_lines_comments_and_valid_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "etc").mkdir()
            (root / "etc/passwd").write_text("\n# fixture\nroot:x:0:0::/:/bin/sh\n")
            (root / "etc/group").write_text("\n# fixture\nwheel:x:10:alice\n")
            self.assertEqual(checks.privileges(root).status, "INFO")

    def test_sshd_malformed_values_are_unknown(self):
        valid = "permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\n"
        for text in (valid.replace("permitrootlogin no", "permitrootlogin typo"), valid.replace("pubkeyauthentication yes", "pubkeyauthentication maybe")):
            self.assertEqual(checks.ssh(lambda _: checks.Command(0, text)).status, "UNKNOWN")
