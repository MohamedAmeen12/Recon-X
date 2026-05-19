# ReconX — AI-Powered Cybersecurity Reconnaissance Platform

ReconX is a full-stack, ML-driven web application for automated security reconnaissance and vulnerability assessment. It orchestrates a seven-stage intelligence pipeline — from subdomain discovery to actionable remediation — backed by machine learning models, graph-based attack path analysis, and Google Gemini AI.

---

## Overview

ReconX takes a target domain and runs it through an end-to-end pipeline that discovers assets, scans ports, detects vulnerabilities, scores risk, and generates prioritized remediation recommendations — all exposed via a web UI, REST API, and CLI.

---

## Architecture

**Stack:** Python · Flask · MongoDB · Neo4j · XGBoost · NetworkX · Google Gemini

```
┌─────────────────────────────────────────────────────────────────┐
│                        ReconX Platform                          │
│                                                                 │
│  Web UI (Flask/Jinja2)  ←→  REST API  ←→  CLI (reconx_cli.py)  │
│                                                                 │
│  ┌──────────────────────── ML Pipeline ────────────────────┐   │
│  │  M1: Discovery → M2: Port Scan → M3: Fingerprint/Vulns  │   │
│  │  M4: Anomaly Detection → M5: Exploit Graph              │   │
│  │  M6: Risk Scoring (XGBoost) → M7: Recommendations       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  MongoDB  ·  Neo4j  ·  Gemini AI  ·  NVD API  ·  EPSS API     │
└─────────────────────────────────────────────────────────────────┘
```

---

## The 7-Model Pipeline

### Model 1 — Subdomain Discovery
Uses **subfinder** and **amass** to enumerate subdomains, then applies ML clustering and LSTM anomaly detection to flag outlier/suspicious subdomains.

### Model 2 — High-Speed Port Scanning
Uses **masscan** to perform full 65535-port sweeps with DNS resolution fallback. Results feed all downstream models.

### Model 3 — Fingerprinting & Vulnerability Detection
- **httpx** — tech stack detection, HTTP headers, status codes (with rate-limit retry)
- **katana** — deep endpoint crawling with JavaScript analysis
- **ffuf** — directory brute-forcing
- **nuclei** — template-based vulnerability scanning with deduplication
- ML Decision Tree filter to remove false positives before surfacing findings

### Model 4 — HTTP Anomaly Detection
LSTM-based anomaly detector trained on HTTP response features (status codes, content lengths). Flags anomalous endpoints for elevated attention.

### Model 5 — Exploitation Strategy (Attack Graph)
Builds a directed graph of the target's attack surface using **NetworkX** and syncs it to **Neo4j**. Fetches real **EPSS scores** (Exploit Prediction Scoring System) concurrently per CVE, weights edges by exploit probability, and runs **Dijkstra's algorithm** to find the path of least resistance from Internet to internal assets.

### Model 6 — Vulnerability Risk Scoring
**XGBoost** gradient-boosting classifier that takes 13 engineered features (CVSS, EPSS, exploit availability, subdomain count, anomaly flags, etc.) and outputs a prioritized risk label: Critical / High / Medium / Low. Overrides are applied when Active Validator confirms exploit status (Exploitable / Patched / Blocked by WAF). Results stored in MongoDB.

### Model 7 — Recommendation Engine
NLP-driven (TF-IDF) engine that produces per-vulnerability reports including:
- CWE-aware explanation (8 CWE types mapped with behavior, impact, and attack variants)
- Step-by-step attack chain simulation
- Confidence level (HIGH / MEDIUM / LOW / PATCHED / MITIGATED)
- MITRE ATT&CK technique mapping
- Actionable remediation steps grouped as: Immediate Fix · Hardening · Monitoring
- Auto-generated PowerShell remediation scripts
- CVE metadata enriched from the **NVD API**

---

## Key Features

| Feature | Detail |
|---|---|
| **Active Validator** | WAF detection via benign XSS probe; exploit simulation via Nuclei |
| **Delta Scanning** | Tracks NEW / EXISTING / MISSING_PENDING / RESOLVED findings across scans |
| **AI Assistant** | Google Gemini 2.5 Flash + Pro (with fallback) answers questions about scan results |
| **Export Formats** | Burp Suite replay requests · JSON · Markdown |
| **Authentication** | Session-based auth, closed-by-default route guard, role-based (user/admin) |
| **Security Hardening** | SSRF protection, path traversal blocking, rate limiting, audit logging |
| **CLI Mode** | `reconx_cli.py` for headless scanning with `X-CLI-Bypass` header |
| **Admin Panel** | User management, scan history, strategy statistics |

---

## Technology Dependencies

**External Tools (must be in PATH or `~/go/bin/`):**
- `subfinder`, `amass`, `httpx`, `katana`, `nuclei`, `ffuf` (Go-based)
- `masscan.exe` (requires admin/raw socket access)

**Python Libraries:**
- `flask`, `flask-cors`, `flask-limiter`
- `xgboost`, `scikit-learn`, `pandas`, `numpy`, `joblib`
- `networkx`, `neo4j`
- `pymongo`
- `google-generativeai`
- `requests`, `python-dotenv`

**Services:**
- MongoDB (default: `reconx_db`)
- Neo4j (default: `bolt://localhost:7687`)
- Google Gemini API key (`GEMINI_API_KEY`)
- NVD API key (optional, for CVE enrichment)

---

## Quick Start

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Set environment variables
cp .env.example .env
# Edit .env: GEMINI_API_KEY, SECRET_KEY, MONGO_URI, NVD_API_KEY

# 3. Start MongoDB and Neo4j

# 4. Seed the admin user
python utils/seed_admin.py

# 5. Run the application
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
├── app.py                    # Flask app, blueprints, auth guard
├── recon_pipeline.py         # Models 1–5 orchestration
├── recon_ml_enhancements.py  # ML helpers (LSTM, Decision Tree, etc.)
├── reconx_cli.py             # CLI scanner
├── models/
│   ├── model6_vulnerability_risk.py   # XGBoost risk scorer
│   └── model7_recommendation_engine.py # NLP recommendation engine
├── controllers/              # Flask blueprints (scan, report, auth, admin, AI)
├── utils/
│   ├── gemini_service.py     # Google Gemini integration
│   ├── nvd_api_tool.py       # NVD CVE enrichment
│   ├── report_generator.py   # Report assembly
│   └── ssrf_protection.py    # SSRF guard
├── exports/
│   ├── burp_exporter.py      # Burp Suite export
│   ├── json_exporter.py
│   └── markdown_exporter.py
├── pipeline/
│   └── pipeline_controller.py
└── views/                    # Jinja2 templates
```

---

## Security Notes

- All routes are authenticated by default; public routes are explicitly whitelisted.
- File downloads enforce path traversal prevention and directory containment.
- SSRF protection blocks internal IP ranges on all outbound requests.
- Rate limiting is applied globally via Flask-Limiter.
- Audit logger records all scan and auth events.
