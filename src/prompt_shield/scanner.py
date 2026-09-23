from __future__ import annotations

from dataclasses import dataclass, asdict
import re
from typing import Iterable

@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    pattern: re.Pattern[str]
    message: str

@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    message: str
    start: int
    end: int
    excerpt: str

    def to_dict(self) -> dict:
        return asdict(self)

@dataclass(frozen=True)
class ScanResult:
    findings: tuple[Finding, ...]
    score: int
    level: str

    @property
    def safe(self) -> bool:
        return not self.findings

    def to_dict(self) -> dict:
        return {"safe": self.safe, "score": self.score, "level": self.level,
                "findings": [f.to_dict() for f in self.findings]}

RULES: tuple[Rule, ...] = (
    Rule("PI001", "instruction_override", "high", re.compile(r"\b(ignore|disregard|forget)\b.{0,50}\b(previous|prior|above|system|developer)\b.{0,30}\b(instruction|message|prompt|rule)s?\b", re.I | re.S), "Attempts to override earlier instructions."),
    Rule("PI002", "prompt_exfiltration", "high", re.compile(r"\b(reveal|show|print|repeat|expose|dump)\b.{0,60}\b(system prompt|developer message|hidden instruction|internal prompt)\b", re.I | re.S), "Requests hidden or privileged prompt content."),
    Rule("PI003", "role_manipulation", "medium", re.compile(r"\b(you are now|act as|pretend to be|enter)\b.{0,50}\b(unrestricted|unfiltered|developer mode|jailbreak|DAN)\b", re.I | re.S), "Attempts suspicious role or mode manipulation."),
    Rule("PI004", "tool_abuse", "high", re.compile(r"\b(run|execute|call|use)\b.{0,40}\b(tool|shell|terminal|command)\b.{0,80}\b(without|bypass|ignore|no)\b.{0,30}\b(permission|approval|confirmation|restriction)s?\b", re.I | re.S), "Requests tool execution while bypassing controls."),
    Rule("PI005", "data_exfiltration", "high", re.compile(r"\b(send|upload|post|exfiltrate|forward)\b.{0,60}\b(secret|credential|token|password|private key|environment variable)s?\b", re.I | re.S), "Requests transmission of sensitive data."),
)

SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("SEC001", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,})\b")),
    ("SEC002", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("SEC003", re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*['\"]?[A-Za-z0-9_./+\-=]{12,}")),
)

WEIGHTS = {"low": 10, "medium": 25, "high": 40, "critical": 60}

def _excerpt(text: str, start: int, end: int, radius: int = 45) -> str:
    value = text[max(0, start-radius):min(len(text), end+radius)].replace("\n", " ")
    return value[:160]

def scan_text(text: str, *, rules: Iterable[Rule] = RULES) -> ScanResult:
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    findings: list[Finding] = []
    for rule in rules:
        for match in rule.pattern.finditer(text):
            findings.append(Finding(rule.id, rule.category, rule.severity, rule.message, match.start(), match.end(), _excerpt(text, match.start(), match.end())))
    for rule_id, pattern in SECRET_RULES:
        for match in pattern.finditer(text):
            findings.append(Finding(rule_id, "embedded_secret", "critical", "Possible credential or private key embedded in text.", match.start(), match.end(), "[REDACTED SECRET]"))
    findings.sort(key=lambda f: (f.start, f.rule_id))
    score = min(100, sum(WEIGHTS[f.severity] for f in findings))
    level = "critical" if score >= 60 else "high" if score >= 40 else "medium" if score >= 20 else "low" if score else "none"
    return ScanResult(tuple(findings), score, level)

def redact_secrets(text: str) -> str:
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    result = text
    for _, pattern in SECRET_RULES:
        result = pattern.sub("[REDACTED]", result)
    return result
