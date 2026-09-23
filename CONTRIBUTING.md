# Contributing

Contributions are welcome. Keep changes focused and deterministic.

1. Fork and create a feature branch.
2. Use Python 3.10+ and install with `python -m pip install -e .` plus `pytest`.
3. Add tests for every behavior change, especially new detection rules and false-positive fixes.
4. Run `python -m compileall -q src` and `pytest -q`.
5. Never commit real credentials or private prompt material; use obviously synthetic test strings.
6. Open a pull request explaining the behavior and trade-offs.

Detection rules should have stable IDs, a clear category/severity, bounded regular expressions, and both positive and benign tests where practical.
