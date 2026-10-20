import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import platform
import sys

from . import __version__
from .checks import CHECKS, Finding


def terminal_safe(value):
    """Do not let filenames or command diagnostics inject terminal controls."""
    return "".join(char if char.isprintable() else f"\\x{ord(char):02x}" for char in str(value))


def demo_findings():
    return [
        Finding("firewall", "INFO", "Input chains found; review their rules",
                ["inet/filter/input: input policy=drop"],
                "DEMO: a drop policy alone does not establish effective filtering.",
                "Inspect rules, their order and IPv4/IPv6 coverage."),
        Finding("ssh", "WARN", "OpenSSH base authentication configuration",
                ["permitrootlogin=no", "passwordauthentication=yes"],
                "DEMO: password authentication is enabled in the base configuration.",
                "Review whether password access is needed. Verify key access before changing settings."),
        Finding("updates", "SKIP", "Online update check was not requested", [],
                "DEMO: no network request was made.", "Use --online for an actual update check."),
        Finding("privileges", "INFO", "Local privilege inventory and sudoers metadata",
                ["Local UID 0 account: root", "wheel supplementary members: demo-user"],
                "DEMO: group membership does not establish effective sudo permissions.", "Inspect sudo -l."),
        Finding("suid", "INFO", "1 SUID/SGID file in selected directories",
                ["/usr/bin/sudo uid=0 gid=0 mode=4755"],
                "DEMO: SUID can be legitimate; file contents were not executed.",
                "Check package ownership of unfamiliar files."),
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evidence-based Arch Linux security observations. No automatic fixes.")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--only", nargs="+", choices=tuple(CHECKS), help="Run selected checks")
    parser.add_argument("--online", action="store_true", help="Allow checkupdates network access and temporary database writes (non-root)")
    parser.add_argument("--strict", action="store_true", help="Exit 2 on UNKNOWN, otherwise 1 on WARN, otherwise 0")
    parser.add_argument("--demo", action="store_true", help="Show fictional findings without inspecting the system")
    args = parser.parse_args(argv)
    if sys.platform != "linux" and not args.demo:
        parser.error("Live checks require Linux. Use --demo on other operating systems.")
    selected = list(dict.fromkeys(args.only or CHECKS))
    if args.demo:
        findings = [item for item in demo_findings() if item.check in selected]
        target = "fictional demo; no host inspection"
    else:
        try:
            distro = platform.freedesktop_os_release()
            target = distro.get("PRETTY_NAME", "Linux")
        except OSError:
            target = "Linux (distribution unknown)"
        findings = []
        for name in selected:
            if args.format == "text":
                print(f"Checking {name}...", file=sys.stderr, flush=True)
            try:
                findings.append(CHECKS[name](online=args.online) if name == "updates" else CHECKS[name]())
            except (OSError, ValueError) as exc:
                findings.append(Finding(name, "UNKNOWN", "Check failed", [str(exc)],
                                        "The observation is incomplete.", "Inspect the error and rerun this check."))
    report = {
        "schema_version": 1, "tool_version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "demo": args.demo, "target": target,
        "summary": dict(Counter(item.status for item in findings)),
        "findings": [item.to_dict() for item in findings],
    }
    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=True))
    else:
        print(f"arch-security-audit {__version__} | {terminal_safe(target)}")
        print("Scope: five limited checks; findings are observations, not a security certification.")
        if not args.demo:
            print("Arch Linux is the supported target; other distributions may return UNKNOWN.")
        for item in findings:
            print(f"\n[{item.status}] {item.check}: {terminal_safe(item.title)}")
            for evidence in item.evidence:
                print(f"  - {terminal_safe(evidence)}")
            print(f"  Why: {terminal_safe(item.explanation)}")
            print(f"  Next: {terminal_safe(item.suggestion)}")
        print("\nSummary: " + ", ".join(f"{count} {status}" for status, count in report["summary"].items()))
        print("SKIP means not checked. UNKNOWN means incomplete. INFO is not a pass.")
    if args.strict:
        if any(item.status == "UNKNOWN" for item in findings):
            return 2
        if any(item.status == "WARN" for item in findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
