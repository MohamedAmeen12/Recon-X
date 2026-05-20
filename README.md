# ReconX — AI-Powered Cybersecurity Reconnaissance Platform

ReconX is a full-stack, ML-driven web application for automated security reconnaissance and vulnerability assessment. It orchestrates a seven-stage intelligence pipeline — from subdomain discovery to actionable remediation — backed by machine learning models, graph-based attack path analysis, and Google Gemini AI.

---

## Overview

ReconX takes a target domain and runs it through an end-to-end pipeline that discovers assets, scans ports, detects vulnerabilities, scores risk, and generates prioritized remediation recommendations — all exposed via a web UI, REST API, and CLI.

---

## Architecture

**Stack:** Python · Flask · MongoDB · XGBoost · NetworkX · Google Gemini

```
┌──────────────────────────────────────────────────────────────────────┐
│                         ReconX Platform                              │
│                                                                      │
│   Web UI (Flask/Jinja2)  ←→  REST API  ←→  CLI (reconx_cli.py)     │
│                                                                      │
│   ┌───────────────────────── ML Pipeline ───────────────────────┐   │
│   │  M1: Discovery  →  M2: Port Scan  →  M3: Fingerprint/Vulns  │   │
│   │  M4: Anomaly Detection  →  M5: Exploit Graph                 │   │
│   │  M6: Risk Scoring (XGBoost)  →  M7: Recommendations          │   │
│   └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│   MongoDB · Gemini AI · NVD API · EPSS API · Npcap/tcpdump          │
└──────────────────────────────────────────────────────────────────────┘
```

---

## The 7-Model Pipeline

### Model 1 — Subdomain Discovery
Three engines run **in parallel** and results are merged + deduplicated:
- **subfinder** (primary, fast passive enumeration)
- **amass** (comprehensive OSINT enumeration)
- **sublist3r** (Python-based fallback)

Then: DNS resolution, HTTP liveness probing, KMeans clustering, dead-subdomain filtering.

### Model 2 — Port Scanning & Service Detection
Tiered scanning strategy — best available tool wins:

| Tier | Tool | Coverage | Notes |
|---|---|---|---|
| 1 | **masscan** | All 65 535 ports | Requires admin; built from source |
| 2 | **nmap** | Service detection on open ports | python-nmap wrapper |
| 3 | **Concurrent socket scan** | 80 curated ports | Pure Python fallback, parallel, ~0.5 s |

After port discovery, an **AI Port Service** (Random Forest, 88 % accuracy, trained on 10 000 synthetic samples) classifies each open port into service name + version using banner text as TF-IDF features.

### Model 3 — Technology Fingerprinting & Vulnerability Detection
Full pipeline per subdomain:
1. **httpx** — primary tech-stack detection (Server header, X-Powered-By, technology tags)
2. **HTTP header analysis** — always-on fallback
3. **NVD API lookup** — CVEs fetched with process-level caching; results include both confirmed (version-range matched) and potential (no range data) findings
4. **Active Validator** — WAF detection + Nuclei CVE template validation (15 s timeout)

**Crawling extension** (runs in background, does not block the scan):
- **Katana** — JS-aware deep crawl → endpoint discovery
- **ffuf** — directory brute-force on crawled endpoints
- **JS Analyzer** — regex extraction of hidden API routes, GraphQL, Swagger refs
- **Nuclei extended** — broad endpoint scan on all discovered URLs
- **AI Validator** — Gemini confidence scoring of crawling findings

Export quality: deduplication by `(service_name, version, cve_id)`, generic placeholder entries removed, full NVD descriptions preserved.

### Model 4 — HTTP & Traffic Anomaly Detection
**Two-layer detection — both run for every subdomain:**

**Layer 1 — Rule-based signals (always active):**
- Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- CORS wildcard (`Access-Control-Allow-Origin: *`)
- Server version header exposure
- Insecure cookies (missing Secure/HttpOnly flags)
- High HTTP error rate

**Layer 2 — ML anomaly scoring (Isolation Forest):**
- Trained on HTTP baseline from 5 production domains
- 12-feature vector: HTTP misconfigs + live traffic metrics
- Status: `suspicious` when Isolation Forest score < 0 OR critical rule signals fire

**Traffic capture (tcpdump — built from source):**
- Binary: `tcpdump.exe` in project root (built from [the-tcpdump-group/tcpdump](https://github.com/the-tcpdump-group/tcpdump) v5.0.0)
- Interface: auto-detected by matching local outbound IP to NPF device name
- BPF filter: `host <target_ip>` — only target-relevant packets
- pcap parsed with pure-Python `struct.unpack` reader — no extra libraries
- Runs as a subprocess (avoids Npcap threading deadlocks in the main process)
- Falls back to Scapy if tcpdump binary is unavailable

### Model 5 — Exploitation Strategy (Attack Graph)
Uses Exploit-DB references and Q-Learning to build attack chains mapped to MITRE ATT&CK techniques. Outputs strategies with confidence levels (Public Exploit / Active Proof) and remediation guidance.

### Model 6 — Vulnerability Risk Scoring
**XGBoost** gradient-boosting classifier (multi-class: Critical / High / Medium / Low).
- 13 engineered features: CVSS, EPSS score, exploit availability, subdomain count, anomaly flags, traffic anomaly score, port exposure, etc.
- Active Validator overrides: Exploitable → promoted to Critical/High; Patched → downgraded
- Results stored in MongoDB `vulnerability_risk_scores` collection

### Model 7 — Recommendation Engine
NLP-driven (TF-IDF + CWE mapping) per-vulnerability reports:
- 8 CWE types with randomised behavior/impact/attack variants
- Step-by-step attack chain simulation
- Confidence levels: HIGH / MEDIUM / LOW / PATCHED / MITIGATED
- MITRE ATT&CK technique IDs
- Service-aware remediation (Apache, nginx, PHP, MySQL, OpenSSH, WordPress, etc.)
- Auto-generated PowerShell remediation scripts
- CVE metadata from **NVD API** (CPE-first lookup → keyword fallback)

---

## Key Features

| Feature | Detail |
|---|---|
| **Parallel subdomain discovery** | subfinder + amass + sublist3r run simultaneously, merged |
| **CVE cache** | Process-level cache prevents re-querying NVD for same tech/version |
| **Parallel CVE lookups** | All technologies in a URL processed concurrently (5 workers) |
| **Background crawling** | Katana + ffuf + Nuclei run after scan completes — never blocks report |
| **Active Validator** | WAF detection via benign XSS probe; Nuclei CVE validation (15 s limit) |
| **Delta Scanning** | Tracks NEW / EXISTING / MISSING_PENDING / RESOLVED across scans |
| **AI Assistant** | Google Gemini 2.5 Flash + Pro answers questions about scan results |
| **Export formats** | Burp Suite replay · JSON (deduplicated) · Markdown (service-aware remediation) |
| **Authentication** | Session-based auth, closed-by-default route guard, role-based (user/admin) |
| **Security hardening** | SSRF protection, path traversal blocking, rate limiting, audit logging |
| **CLI mode** | `reconx_cli.py` for headless scanning with `X-CLI-Bypass` header |
| **Report loading** | Export pipeline runs in background — report page loads instantly |
| **PDF reports** | wkhtmltopdf integration for downloadable PDF security reports |

---

## Installed Tools

All binaries are in `~/go/bin/` (Go tools) or the project root (compiled tools):

### Go Tools (`~/go/bin/`)
| Tool | Version | Purpose |
|---|---|---|
| **subfinder** | v2.14.0 | Passive subdomain enumeration |
| **amass** | v4 | Comprehensive OSINT subdomain discovery |
| **httpx** | latest | Technology fingerprinting, HTTP probing |
| **katana** | latest | JS-aware web crawler |
| **nuclei** | v3.8.0 | CVE template scanning, active validation |
| **ffuf** | v2.1.0 | Directory brute-forcing |

### Compiled from Source (project root)
| Binary | Source | Purpose |
|---|---|---|
| **masscan.exe** | [robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) v1.3.9 | High-speed full-range port scanner |
| **tcpdump.exe** | [the-tcpdump-group/tcpdump](https://github.com/the-tcpdump-group/tcpdump) v5.0.0 | Packet capture for Model 4 anomaly detection |

### System Tools
| Tool | Purpose |
|---|---|
| **nmap** | Service-version detection on open ports |
| **wkhtmltopdf** | PDF report generation |
| **Npcap** | Packet capture driver (required by tcpdump and masscan) |

---

## Trained Models

All model artifacts are pre-trained and stored in `models/artifacts/` and `saved_models/`:

| Model | Algorithm | Artifact | Accuracy |
|---|---|---|---|
| Model 3 (vulnerability classification) | Logistic Regression + TF-IDF | `model3_lr.pkl`, `model3_tfidf.pkl` | — |
| Model 4 (anomaly detection) | Isolation Forest | `model4_iforest.pkl` | Unsupervised |
| Model 5 (exploitation strategy) | Q-Learning | `model5_qtable.pkl` | — |
| Model 6 (risk scoring) | XGBoost multi-class | `model6_risk_model.pkl` | — |
| AI Port Service | Random Forest + SVM | `saved_models/ai_port_service/` | 88 % |

---

## Python Stack

| Package | Version | Use |
|---|---|---|
| flask | 3.1.1 | Web framework |
| pymongo | 4.16.0 | MongoDB driver |
| xgboost | 3.2.0 | Model 6 risk scoring |
| scikit-learn | 1.8.0 | Models 3, 4, AI Port Service |
| numpy | 2.2.4 | Numerical features |
| pandas | 3.0.2 | Data processing |
| scapy | 2.7.0 | Packet capture fallback |
| google-generativeai | — | Gemini AI assistant |
| sublist3r | — | Subdomain discovery |
| python-nmap | 0.7.1 | nmap Python wrapper |

---

## Quick Start

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Set environment variables
cp .env.example .env
# Edit .env: GEMINI_API_KEY, SECRET_KEY, MONGO_URI, NVD_API_KEY

# 3. Start MongoDB

# 4. Seed the admin user
python utils/seed_admin.py

# 5. Update nuclei templates
nuclei -update-templates

# 6. Run the application
python app.py
# → http://localhost:5000
```

**CLI Usage:**
```bash
python reconx_cli.py --target example.com --server http://localhost:5000
```

---

## Project Structure

```
ReconX/
├── app.py                          # Flask app, blueprints, auth guard
├── reconx_cli.py                   # Headless CLI scanner
├── masscan.exe                     # Built from source (robertdavidgraham/masscan)
├── tcpdump.exe                     # Built from source (the-tcpdump-group/tcpdump)
├── pcap.dll / Packet.dll / wpcap.dll  # Npcap runtime DLLs for tcpdump
├── models/
│   ├── model1.py                   # Subdomain discovery (subfinder+amass+sublist3r)
│   ├── model2.py                   # Port scanning (masscan→nmap→socket+AI classifier)
│   ├── model3.py                   # Tech fingerprinting + NVD CVE lookup (parallel)
│   ├── model4.py                   # HTTP anomaly detection (rule-based + IsolationForest)
│   ├── model5.py                   # Exploitation strategy (Q-Learning + MITRE ATT&CK)
│   ├── model6_vulnerability_risk.py  # XGBoost risk scorer
│   ├── model7_recommendation_engine.py  # NLP recommendation engine
│   ├── active_validator.py         # WAF detection + Nuclei active validation
│   ├── crawling/                   # Background crawling extension (Katana+ffuf+JS)
│   │   ├── pipeline.py             # Crawling orchestrator
│   │   ├── crawler.py              # Katana / hakrawler / built-in fallback
│   │   ├── js_analyzer.py          # JS endpoint extraction (regex)
│   │   ├── endpoint_collector.py   # Aggregation + dedup + parameter extraction
│   │   ├── nuclei_extended.py      # Broad endpoint Nuclei scan
│   │   └── ai_validator.py         # Gemini confidence scoring
│   ├── ai_port_service/            # RF+SVM port service classifier
│   └── artifacts/                  # Trained model pkl files
├── controllers/                    # Flask blueprints (scan, report, auth, admin, AI)
├── utils/
│   ├── traffic_collector.py        # tcpdump/Scapy packet capture for Model 4
│   ├── http_collector.py           # HTTP feature extraction for Model 4
│   ├── tech_fingerprint_tool.py    # httpx + HTTP header fingerprinting
│   ├── gemini_service.py           # Google Gemini AI integration
│   ├── nvd_api_tool.py             # NVD API CVE enrichment
│   ├── report_generator.py         # HTML/PDF report assembly
│   ├── ssrf_protection.py          # SSRF guard
│   └── audit_logger.py             # Tamper-resistant audit log
├── exports/
│   ├── burp_exporter.py            # Burp Suite replay export
│   ├── json_exporter.py            # JSON export (deduped, with NVD refs)
│   └── markdown_exporter.py        # Markdown export (service-aware remediation)
├── pipeline/
│   └── pipeline_controller.py      # Export pipeline orchestrator
├── saved_models/                   # XGBoost + AI Port Service pkl files
├── views/                          # Jinja2 HTML templates
└── static/                         # CSS, JS, assets
```

---

## Security Notes

- All routes are authenticated by default; public routes are explicitly whitelisted.
- File downloads enforce path traversal prevention and directory containment.
- SSRF protection blocks internal/private IP ranges on all outbound requests.
- Rate limiting is applied globally via Flask-Limiter (5 scans/hour per user).
- Audit logger records all scan and auth events with HMAC integrity protection.
- tcpdump and masscan require **Npcap** and typically **administrator privileges** for raw packet access.
