# Security Policy

Prompt Shield is a deterministic heuristic scanner, not a security boundary. Do not treat a clean result as proof that untrusted text is safe. Keep normal authorization, sandboxing, least-privilege tool access, and human approval for consequential actions.

The scanner runs locally and makes no network requests. Findings for detected secrets deliberately replace the matching excerpt with `[REDACTED SECRET]`.

## Reporting vulnerabilities

Please open a GitHub Security Advisory for vulnerabilities when that facility is available. Avoid posting credentials, private prompts, or sensitive samples in public issues.

Supported release line: `1.x`.
