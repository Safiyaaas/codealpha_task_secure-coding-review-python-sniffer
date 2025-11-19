# Secure Coding Review: Python Network Sniffer

This repository contains a complete secure coding review (Task 3) for a basic Python network sniffer application. The review identifies vulnerabilities, provides recommendations, and includes a remediated version of the code.

## Overview
- **Language/Application**: Python / Network Sniffer (using Scapy for packet capture and analysis).
- **Review Method**: Manual inspection + static analysis with Bandit.
- **Key Findings**: Privilege escalation (high severity), data exposure, and misconfiguration risks. See `SECURITY_REVIEW.md` for details.
- **Remediation**: Applied fixes in `secure_sniffer.py` for safer code.

## Requirements
- Python 3.x
- Install dependencies: `pip install -r requirements.txt`
- Run with admin privileges (e.g., `sudo python secure_sniffer.py`).

## Usage
1. Original code: `python sniffer.py` (requires setup; see SECURITY_REVIEW.md for risks).
2. Secure code: `python secure_sniffer.py` (includes safeguards).
3. Review the full report in `SECURITY_REVIEW.md`.

## Tools Used
- Bandit (static analyzer): `bandit sniffer.py`
- Manual code inspection for logic and best practices.

## Recommendations
- Follow OWASP guidelines for Python.
- Test thoroughly and avoid running sniffers on untrusted networks.
- Contribute or report issues via GitHub.
