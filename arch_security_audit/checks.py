"""Checks report observations, never a universal 'secure system' verdict."""

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess


@dataclass
class Finding:
    check: str
    status: str
    title: str
    evidence: list[str]
    explanation: str
    suggestion: str

    def to_dict(self):
        return asdict(self)


@dataclass
class Command:
    code: int | None
    out: str = ""
    error: str = ""


def run(argv: list[str], timeout: int = 30) -> Command:
    # Do not execute a lookalike binary from the current directory or user PATH.
    trusted_path = "/usr/sbin:/usr/bin:/sbin:/bin"
    executable = shutil.which(argv[0], path=trusted_path)
    if executable is None:
        return Command(None, error=f"{argv[0]} is not installed in a system directory")
    env = {**os.environ, "LC_ALL": "C", "PATH": trusted_path}
    try:
        result = subprocess.run(
            [executable, *argv[1:]], capture_output=True, text=True,
            errors="replace", timeout=timeout, env=env, check=False,
        )
        return Command(result.returncode, result.stdout, result.stderr)
    except subprocess.TimeoutExpired:
        return Command(None, error=f"Command timed out after {timeout}s")
    except OSError as exc:
        return Command(None, error=str(exc))


def unavailable(check, result, suggestion):
    detail = (result.error or f"Exit status {result.code}").strip()[:1000]
    return Finding(check, "UNKNOWN", "Could not complete this check", [detail],
                   "Missing tools, permissions or command errors are not a successful check.",
                   suggestion)


def firewall(runner=run):
    result = runner(["nft", "-j", "list", "ruleset"])
    if result.code != 0:
        return unavailable("firewall", result,
                           "Inspect nftables with sufficient permissions. Legacy iptables is outside this check.")
    try:
        objects = json.loads(result.out)["nftables"]
        if not isinstance(objects, list):
            raise ValueError("nftables must be an array")
        chains = []
        for item in objects:
            if not isinstance(item, dict):
                raise ValueError("Unexpected nftables object")
            chain = item.get("chain")
            if chain is not None:
                if not isinstance(chain, dict):
                    raise ValueError("Unexpected chain object")
                if chain.get("hook") == "input" and chain.get("family") in {"ip", "ip6", "inet"}:
                    chains.append(chain)
    except (ValueError, KeyError, TypeError) as exc:
        return unavailable("firewall", Command(None, error=f"Invalid nft JSON: {exc}"),
                           "Check the installed nftables version and inspect its ruleset manually.")
    evidence = [f"{c.get('family')}/{c.get('table')}/{c.get('name')}: input policy={c.get('policy', 'unspecified')}"
                for c in chains]
    return Finding(
        "firewall", "INFO" if chains else "WARN",
        "Input chains found; review their rules" if chains else "No IP/IPv6 nftables input base chains found",
        evidence or ["nftables ruleset contains no matching input base chains"],
        "A chain policy alone does not prove filtering is effective. Earlier accept rules, rule order, "
        "IPv4/IPv6 coverage, other hooks and network namespaces require review. "
        "This check does not inspect legacy iptables, eBPF or an upstream firewall.",
        "Review: sudo nft list ruleset. Decide which inbound services should be reachable.",
    )


def ssh(runner=run):
    result = runner(["sshd", "-T"])
    if result.code != 0:
        return unavailable("ssh", result,
                           "If you use OpenSSH server, inspect sshd -T with sufficient permissions. "
                           "An absent SSH server may be intentional.")
    settings = {}
    for line in result.out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            settings[parts[0].lower()] = parts[1]
    keys = ("permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication")
    if any(key not in settings for key in keys):
        return unavailable("ssh", Command(None, error="sshd output is missing expected authentication settings"),
                           "Inspect sshd -T manually.")
    risky = (settings["permitrootlogin"] == "yes" or settings["passwordauthentication"] == "yes"
             or settings["kbdinteractiveauthentication"] == "yes")
    return Finding(
        "ssh", "WARN" if risky else "INFO", "OpenSSH base authentication configuration",
        [f"{key}={settings[key]}" for key in keys],
        "sshd -T evaluates the configuration on disk, including Include files and defaults. "
        "It does not establish whether a server is running or reachable, or whether it loaded these settings. "
        "Without -C, connection-specific Match rules are not evaluated. Keyboard-interactive may be used for MFA.",
        "Review these options for your use case. Test key access before disabling password login; "
        "use sshd -T -C with your connection details to inspect Match rules.",
    )


def updates(online=False, runner=run):
    if not online:
        return Finding("updates", "SKIP", "Online update check was not requested", [],
                       "A cached pacman database cannot establish that the system is up to date.",
                       "Run as a regular user with --online and pacman-contrib installed.")
    if os.geteuid() == 0:
        return Finding("updates", "SKIP", "Run the online check as a regular user", [],
                       "checkupdates synchronizes a separate temporary package database; avoid doing that as root.",
                       "Run python -m arch_security_audit --only updates --online without sudo.")
    result = runner(["checkupdates"], timeout=120)
    if result.code not in {0, 2}:
        return unavailable("updates", result, "Check connectivity, mirrors and pacman-contrib installation.")
    packages = [line for line in result.out.splitlines() if line.strip()]
    if (result.code == 2 and packages) or (result.code == 0 and not packages):
        return unavailable("updates", Command(None, error="Inconsistent checkupdates exit status and output"),
                           "Run checkupdates manually and inspect its output.")
    return Finding(
        "updates", "INFO" if packages else "PASS",
        f"{len(packages)} repository package updates available" if packages else "No repository updates reported",
        packages,
        "checkupdates uses a separate database. Available updates are not automatically security vulnerabilities. "
        "AUR packages and vulnerability feeds are outside this check.",
        "Review Arch news before a full system upgrade with pacman -Syu." if packages
        else "Repeat periodically; this observation only applies to configured repositories at check time.",
    )


def privileges(root=Path("/")):
    evidence, risks, errors = [], [], []
    try:
        for line in (root / "etc/passwd").read_text().splitlines():
            parts = line.split(":")
            if len(parts) != 7 or not parts[2].isdigit():
                errors.append("Malformed /etc/passwd entry")
                continue
            if int(parts[2]) == 0:
                evidence.append(f"Local UID 0 account: {parts[0]}")
                if parts[0] != "root":
                    risks.append(f"Additional UID 0 account: {parts[0]}")
        for line in (root / "etc/group").read_text().splitlines():
            parts = line.split(":")
            if len(parts) == 4 and parts[0] in {"wheel", "sudo"}:
                evidence.append(f"{parts[0]} supplementary members: {parts[3] or '(none)'}")
    except OSError as exc:
        errors.append(str(exc))
    sudoers = root / "etc/sudoers"
    sudo_dir = root / "etc/sudoers.d"
    targets = [sudoers]
    try:
        if sudo_dir.exists():
            targets.append(sudo_dir)
            targets.extend(sudo_dir.iterdir())
    except OSError as exc:
        errors.append(str(exc))
    for path in targets:
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                errors.append(f"Symlink not evaluated: {path}")
                continue
            if info.st_uid != 0 or info.st_mode & 0o022:
                risks.append(f"Review ownership/permissions: {path} uid={info.st_uid} mode={stat.S_IMODE(info.st_mode):04o}")
        except FileNotFoundError:
            if path != sudoers:
                errors.append(f"Disappeared during check: {path}")
            else:
                evidence.append("/etc/sudoers is absent")
        except OSError as exc:
            errors.append(str(exc))
    return Finding(
        "privileges", "UNKNOWN" if errors else ("WARN" if risks else "INFO"),
        "Local privilege inventory and sudoers metadata", evidence + risks + errors,
        "wheel/sudo membership does not prove sudo authorization. This check does not resolve sudoers rules, "
        "external includes, primary group membership, LDAP, polkit, doas or file capabilities. "
        "Metadata is inspected without reading sudoers contents. Containers/user namespaces may remap owner IDs. "
        "UNKNOWN takes priority if any part of this inventory could not be inspected; review all evidence.",
        "Review unexpected UID 0 accounts and writable sudoers paths. Use sudo -l for your effective sudo rules.",
    )


def suid(root=Path("/"), limit=20000):
    found, errors, scanned = [], [], 0
    def onerror(exc):
        errors.append(str(exc))
    for relative in ("usr/bin", "usr/local/bin"):
        directory = root / relative
        try:
            directory.stat()
        except FileNotFoundError:
            errors.append(f"Scan directory absent: /{relative}")
            continue
        except OSError as exc:
            errors.append(str(exc))
            continue
        for base, _, files in os.walk(directory, followlinks=False, onerror=onerror):
            for name in files:
                scanned += 1
                if scanned > limit:
                    return Finding("suid", "UNKNOWN", "SUID/SGID scan limit reached", found + errors,
                                   f"Stopped after {limit} entries; scan is incomplete.",
                                   "Inspect the selected directories manually.")
                path = Path(base) / name
                try:
                    info = path.lstat()
                    if stat.S_ISREG(info.st_mode) and info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                        shown = "/" + str(path.relative_to(root))
                        found.append(f"{shown} uid={info.st_uid} gid={info.st_gid} mode={stat.S_IMODE(info.st_mode):04o}")
                except OSError as exc:
                    errors.append(str(exc))
    return Finding(
        "suid", "UNKNOWN" if errors else "INFO", f"{len(found)} SUID/SGID files in selected directories",
        sorted(found) + errors,
        f"Inspected {scanned} entries under /usr/bin and /usr/local/bin, without following nested symlinks. "
        "Special permission bits can be legitimate. Other paths, mount options and file capabilities are outside scope.",
        "Review unfamiliar files with pacman -Qo /path/to/file and stat. Unowned files are not automatically malicious.",
    )


CHECKS = {"firewall": firewall, "ssh": ssh, "updates": updates, "privileges": privileges, "suid": suid}
