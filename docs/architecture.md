
---

# 📁 `docs/architecture.md`

```markdown
# Architecture — XSSNIPER

This document describes the internal architecture and design patterns implemented by XSSNIPER.

---

## 1. High-Level System Overview

XSSNIPER is composed of the following core subsystems:

- **GUI Layer (Tkinter):** User interface, controls, state management
- **Scanner Engine:** Request scheduling, crawling, parameter extraction
- **Payload Engine:** Context-aware payload generation and mutation
- **DOM Engine (Optional):** Browser-based validation and sink tracing
- **Reporting Module:** Export utilities for HTML, CSV, and JSON
- **Authentication Module:** Session preparation for authenticated targets
- **WAF Detector:** Behavioral fingerprinting against known patterns
- **Integration Layer:** Nuclei and webhook/OAST interoperability

---

## 2. Control Flow

GUI → Scan Controller → Scanner Core → Payload Engine
→ WAF Detector
→ DOM Engine (optional)
→ Nuclei Integration (optional)
→ Result Aggregator → Reports


---

## 3. Core Components

### 3.1 Scanner Engine
Responsibilities:
- HTTP session handling
- Parameter extraction
- Link exploration (domain-scoped BFS)
- Vulnerability validation callbacks

### 3.2 Payload Engine
Implements:
- HTML, Attribute, JavaScript, URL context payloads
- Mutation strategies (encoding, case variants)
- Blind XSS payload injection

### 3.3 DOM Engine
Uses Selenium for:
- Browser-based payload execution
- Detection of:
  - DOM sinks (`innerHTML`, `eval`, etc.)
  - Stored XSS via form submission

### 3.4 WAF Detection
Performs:
- Header inspection
- Response status correlation
- Pattern-based vendor fingerprinting

### 3.5 Reporting Engine
Exports grouped findings via:
- `CSV` → bug bounty workflows
- `JSON` → Burp Import compatibility
- `HTML` → styled assessment reports

---

## 4. Data Structures

### Finding Object (Grouped)

{
finding: {... base finding metadata ...},
payloads: [...],
confidence: "High" | "Medium" | "Low"
}


### Base Finding Structure


{
url,
param,
payload,
type,
method,
confidence,
poc_url
}


---

## 5. Extensibility Design

The platform supports extension points:
- Custom payload modules
- New vulnerability classifiers
- Alternative rendering engines (Chromium)
- External scanners (ZAP, Nuclei, etc.)

---

## 6. Security Considerations

- No automatic exploitation beyond evidence generation
- No active RCE payloads executed in host context
- Designed for authorized assessment workflows

---

## 7. Technology Stack

| Layer | Technology |
|---|---|
| GUI | Tkinter |
| HTTP | requests |
| Parsing | BeautifulSoup4 |
| DOM Validation | Selenium (optional) |
| Scanner Integration | nuclei (optional) |

---

## Conclusion

XSSNIPER follows a modular architecture suitable for continuous enhancement, integration with existing AppSec tooling, and professional penetration testing delivery processes.


