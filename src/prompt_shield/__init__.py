"""Prompt Shield: local deterministic text-risk scanning."""
from .scanner import Finding, ScanResult, scan_text, redact_secrets

__all__ = ["Finding", "ScanResult", "scan_text", "redact_secrets"]
__version__ = "1.0.0"
