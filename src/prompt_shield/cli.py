from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from . import __version__
from .scanner import scan_text, redact_secrets

def _read(value: str | None, path: str | None) -> str:
    if value is not None:
        return value
    if path:
        return Path(path).read_text(encoding="utf-8")
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise ValueError("provide TEXT, --file PATH, or pipe text through stdin")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="prompt-shield", description="Local prompt-injection and secret-risk scanner")
    p.add_argument("--version", action="version", version=f"Prompt Shield {__version__} — Radwan Abdulhadi Ahmed / @rad03i2")
    sub = p.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan text for risky patterns")
    scan.add_argument("text", nargs="?")
    scan.add_argument("-f", "--file")
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default="high")
    red = sub.add_parser("redact", help="redact likely embedded secrets")
    red.add_argument("text", nargs="?")
    red.add_argument("-f", "--file")
    return p

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        text = _read(args.text, args.file)
        if args.command == "redact":
            print(redact_secrets(text)); return 0
        result = scan_text(text)
        if args.json:
            print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        else:
            print(f"Risk: {result.level} | score={result.score} | findings={len(result.findings)}")
            for f in result.findings:
                print(f"- {f.severity.upper():8} {f.rule_id} {f.message}")
        rank = {"none":0,"low":1,"medium":2,"high":3,"critical":4}
        return 1 if rank[result.level] >= rank[args.fail_on] else 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"prompt-shield: {exc}", file=sys.stderr); return 2

if __name__ == "__main__":
    raise SystemExit(main())
