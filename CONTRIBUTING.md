# Contributing to NetFusion

Thank you for your interest in contributing to the **NetFusion Cyber Investigation Platform**!

---

## Architecture Freeze Notice

> [!IMPORTANT]
> **v1.0 RC1 Release Phase**: NetFusion Phase v1.0 RC1 architecture is frozen. No breaking API changes, canonical object redesigns, or database schema alterations will be accepted for v1.0. Only bug fixes, documentation enhancements, performance optimizations, and security patches are eligible for merge at this time.

---

## How to Contribute

### 1. Reporting Bugs
Before opening an issue, please search existing issues to avoid duplicates. When opening a bug report, use our [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.md) and include:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Relevant error tracebacks and log snippets

### 2. Pull Request Guidelines
1. Fork the repository and create a feature branch off `main` (`git checkout -b fix/issue-description`).
2. Ensure all code follows PEP 8 guidelines and type hinting conventions.
3. Add unit or integration tests for your changes under `tests/`.
4. Verify that all tests pass locally:
   ```bash
   python -m pytest -v
   ```
5. Submit your Pull Request using the [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md).

---

## Development Setup

```bash
# Clone fork
git clone https://github.com/<your-username>/netfusion-agent.git
cd netfusion-agent

# Install dependencies
python -m pip install -r requirements.txt

# Run pytest suite
python -m pytest -v
```
