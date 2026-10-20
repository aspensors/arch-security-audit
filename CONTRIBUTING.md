# Contributing

Run `python -m unittest discover -s tests -v` before submitting changes.

For new checks, describe the observed fact, source of evidence, permissions, failure cases and limits. Return UNKNOWN for unavailable evidence. Do not classify an installed tool or a running service as proof of effective protection. Do not add automatic remediation or network access to default checks.

Include fixture tests for both meaningful findings and incomplete observations. Use synthetic usernames, hostnames and paths in public reports. Never include credentials or private configuration.

Report bugs with the tool/Python version, distribution, exact command and sanitized output. Real Arch testing is particularly helpful; the current CI uses Ubuntu and mocks external commands.
