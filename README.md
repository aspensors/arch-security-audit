# arch-security-audit

Small security checks for Arch Linux, with evidence and explanations you can inspect.

**Status: early 0.2.0 prototype.** The automated suite uses fixtures; testing on real Arch installations is still needed. [Русское руководство](docs/GUIDE_RU.md).

The tool reports what it observed, why it matters, and what to inspect next. It does not compute a security score. Most checks produce inventory or review prompts rather than a pass/fail verdict.

## Quick start

Python 3.11+ and Linux are required for live checks. No third-party Python runtime dependencies.

From this project's directory, no installation is needed:

```bash
python -m arch_security_audit --demo
python -m arch_security_audit
python -m arch_security_audit --format json > audit-report.json
```

The demo is fictional and does not inspect your host, run external commands or access the network. Text output is English; explanations in Russian are in the guide.

Optional installation in an isolated environment:

```bash
python -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/arch-security-audit --help
```

Installing may download build dependencies. There is no need for sudo or system-wide pip installation. Optional system commands: `nft` from `nftables`, `sshd` from `openssh`, `checkupdates` from `pacman-contrib`. Missing tools result in UNKNOWN. Install only what you need; the audit does not require enabling an SSH server.

## Compare two saved reports

```bash
python -m arch_security_audit --format json > before.json
# After reviewing and making your own configuration changes:
python -m arch_security_audit --format json > after.json
python -m arch_security_audit --compare before.json after.json
python -m arch_security_audit --compare before.json after.json --format json
```

Comparison is offline and also works on non-Linux systems. It shows `added`, `removed`, `status_changed`, `details_changed` and `unchanged` checks, with both observations. Evidence order and metadata (timestamps, versions, summary) are ignored. Changes in explanations count as changes. Only schema-1 reports up to 4 MiB with unique check identifiers are accepted; malformed reports and different demo flags or target distributions are rejected.

Verify that the files came from the same host: the report records a distribution, not a machine identity. An update to the distribution label requires reviewing the files separately. A warning changing to UNKNOWN/SKIP is incomplete coverage, not a fix; INFO is not a pass. An absent check means it was not assessed. No severity ranking or automatic fix claim is inferred. Comparison exits 0 when produced (even if changed), 2 on input errors. It supports `--format` only; audit options such as `--strict` do not apply.

## Example (fictional)

```text
[INFO] firewall: Input chains found; review their rules
  - inet/filter/input: input policy=drop
  Why: DEMO: a drop policy alone does not establish effective filtering.
  Next: Inspect rules, their order and IPv4/IPv6 coverage.

[WARN] ssh: OpenSSH base authentication configuration
  - permitrootlogin=no
  - passwordauthentication=yes
```

Every live finding also includes an explanation and suggested manual follow-up.

## Check coverage

| Check | Evidence | Important boundary |
| --- | --- | --- |
| `firewall` | `nft -j list ruleset`, IP/IPv6 input base chains and policies | Does not establish reachability or evaluate all rules. Other hooks, legacy iptables, other namespaces and upstream filters are outside scope. |
| `ssh` | `sshd -T`, four authentication options | Base disk configuration only. Does not establish service state, running configuration or connection-specific Match rules. |
| `updates` | Opt-in `checkupdates` with a 120s timeout | Configured repository updates only; no AUR or CVE assessment. |
| `privileges` | Local UID 0 accounts, wheel/sudo supplementary members, sudoers ownership and mode | Inventory, not a complete authorization analysis. |
| `suid` | Regular SUID/SGID files under `/usr/bin` and `/usr/local/bin` | No file execution, nested symlink traversal, capabilities or whole-system scan. 20,000-entry limit. |

An available package update, password authentication or an SUID file is not by itself proof of a vulnerability. Each finding needs context. Backups cannot be assessed merely by detecting installed software, so this release does not attempt that.

## Options and permissions

```bash
python -m arch_security_audit --only privileges suid
python -m arch_security_audit --only updates --online
python -m arch_security_audit --demo --format json
python -m arch_security_audit --strict
```

Start without root. `nft` and `sshd -T` may need additional permissions; failures are reported as UNKNOWN. After reviewing the source, you can run only those offline checks with elevated permissions:

```bash
sudo /usr/bin/python -m arch_security_audit --only firewall ssh
```

Run this from the project directory, and only from a checkout you trust. System commands are resolved from `/usr/sbin:/usr/bin:/sbin:/bin`, not your user PATH. No shell evaluation is used. Text output escapes terminal control characters from filenames and command errors.

The default run does not intentionally modify system configuration or contact the network. `--online` explicitly permits `checkupdates` to access configured mirrors and write a separate temporary database/cache. It is skipped when run as root. No automatic fixes, package upgrades, service restarts or telemetry are implemented. Python itself can create bytecode caches; external commands may have ordinary OS logging side effects.

## Statuses and exit codes

| Status | Meaning |
| --- | --- |
| PASS | A narrow check succeeded, such as no updates reported by checkupdates. |
| WARN | Review a potentially risky observation in your context. |
| INFO | Inventory or configuration evidence; not a pass. |
| UNKNOWN | Missing permission/tool, invalid output, scan limit or another incomplete check. |
| SKIP | Check was deliberately not performed. |

Default exit code: 0 when a report is produced, even with findings. `--strict`: 2 if any UNKNOWN exists, otherwise 1 if any WARN exists, otherwise 0. SKIP/INFO are not failures, so strict exit 0 does not imply full coverage. Invalid CLI arguments exit 2. JSON stdout contains a single object, with `schema_version`, tool version, UTC time, demo marker, target distribution, status counts and findings; progress messages are never mixed into JSON stdout. Review UNKNOWN/SKIP explicitly in automation.

Reports may contain local usernames, file paths, package versions and command diagnostics. Review reports before publishing; prefer the fictional example for your public repository.

## Development

```bash
python -m unittest discover -s tests -v
```

Tests use temporary fixtures and mocked commands, including missing permissions, invalid JSON, checkupdates exit codes, scan limits and CLI exit codes. The GitHub Actions workflow runs the suite and an installation smoke test on Python 3.11–3.14, on Ubuntu. That is not a real Arch integration test.

See [CONTRIBUTING.md](CONTRIBUTING.md). Useful next contributions: sanitized real Arch test cases, effective SSH Match contexts, separate IPv4/IPv6 coverage reporting and an optional integration test in an Arch VM. This project's focus is small, readable checks and explicit evidence.

## References

- [nft(8)](https://man.archlinux.org/man/nft.8)
- [nftables JSON schema](https://man.archlinux.org/man/libnftables-json.5.en)
- [sshd(8), including -T and -C](https://man.archlinux.org/man/sshd.8)
- [checkupdates(8), including exit codes](https://man.archlinux.org/man/extra/pacman-contrib/checkupdates.8.en)

MIT license. See [LICENSE](LICENSE).
