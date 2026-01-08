# Usage Guide — XSSNIPER

This document provides instructions for running and operating XSSNIPER, including scan configuration, authentication, reporting, and optional modules.

---

## 1. Prerequisites

### Mandatory
- Python 3.9+
- `requests`
- `beautifulsoup4`

### Optional
- `selenium` (DOM XSS validation)
- `nuclei` (extended XSS scanning engine)
- Firefox + Geckodriver (Selenium execution)

---

## 2. Launching the Application

Run from console:

```bash
python3 runner.py

The application window will be displayed with modular tabs.

3. Scanner Overview
Target URL

Specify a full URL including protocol:

http://example.com/products?id=1

Scan Execution

Press START SCAN to begin

Press STOP to halt execution

Findings appear in real-time in the logger and vulnerability list

4. Vulnerability Details

Upon detection, each finding contains:

Vulnerability Type (Reflected, DOM, Stored, SSTI, etc.)

Payloads used

Parameter / Method

Proof-of-Concept URL

Confidence Level

Description (if available)

5. Options Overview

The Options panel provides configurable parameters:

Setting	Description
Workers	Parallel scan threads
Crawl Depth	Maximum traversal depth
OOB Domain	Blind XSS webhook endpoint
DOM Mode	DOM validation via Selenium
Mutations	Context-aware payload mutations
6. Authentication

Supports:

Form-based login

Header-based authentication

Token-based retrieval

Credentials are applied to HTTP session before scanning.

7. Reporting

Export formats:

HTML (styled security report)

CSV (bug bounty submission)

JSON (Burp-compatible issue schema)

Export via:

Save Report → choose export path

8. Blind XSS Support

XSSNIPER injects webhook/OAST payloads which trigger upon execution in secondary systems (admin panels, logs, etc.)

Requires:

Valid webhook endpoint (e.g. interactsh, SecurityTrails)

9. Nuclei Integration (Optional)

If nuclei is installed:

XSS templates are automatically executed

Findings are merged into core results

10. Platform Compatibility

Supported on:

Linux

Windows

macOS
