# Secure Coding Review Report: Python Network Sniffer

## Task Overview
This report fulfills Task 3: Secure Coding Review. We selected Python as the language and audited a basic network sniffer application (built with Scapy). The goal was to identify vulnerabilities, use tools/manual inspection, provide recommendations, and document remediation for safer code.

## Review Process
1. **Selection**: Python/sniffer app – Relevant due to network access and data handling risks.
2. **Methods**:
   - **Manual Inspection**: Line-by-line review for logic flaws, insecure patterns, and OWASP Top 10 compliance (e.g., injection, privilege issues).
   - **Static Analysis**: Used Bandit (`pip install bandit`; run `bandit sniffer.py`). It flagged issues like hardcoded interfaces and potential privilege risks.
3. **Scope**: Focused on code-level security (e.g., no runtime testing). Assessed impact on confidentiality, integrity, and availability.
4. **Tools Output**: Bandit identified medium-severity issues (e.g., hardcoded binds). Manual review added context.

## Findings
