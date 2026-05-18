# ReconX — AI-Powered Reconnaissance & Vulnerability Assessment Platform

ReconX is a full-stack web application that automates cybersecurity reconnaissance for authorized targets. It orchestrates a pipeline of seven specialized ML/AI models — from subdomain discovery through exploitation strategy generation — and presents the results through a clean dashboard with PDF report export and a Gemini-powered AI assistant.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Project Structure](#project-structure)
- [The AI/ML Pipeline](#the-aiml-pipeline)
- [Controllers (API Layer)](#controllers-api-layer)
- [Utilities](#utilities)
- [Frontend Views](#frontend-views)
- [Security Design](#security-design)
- [Setup & Installation](#setup--installation)
- [Environment Variables](#environment-variables)
- [Running the Application](#running-the-application)
- [Training the Models](#training-the-models)
- [Tech Stack](#tech-stack)

---

## Architecture Overview

ReconX follows a classic **MVC (Model-View-Controller)** pattern built on Flask:

```
Browser
  │
  ▼
app.py  ──── Global Auth Enforcement (before_request)
  │                │
  │          Rate Limiting (Flask-Limiter)
  │
  ├── controllers/      ← Blueprints — handle HTTP requests
  │       │
  │       ├── calls models/   ← AI/ML pipeline (7 models)
  │       └── calls utils/    ← shared tools & services
  │
  ├── views/            ← Jinja2 HTML templates
  ├── static/           ← CSS + JavaScript (plain fetch-based SPA)
  └── config/           ← MongoDB connection
```

**Database:** MongoDB (via PyMongo). Collections include `users`, `subdomains`, `reports`, `technologies`, `vulnerabilities`, `anomalies`, `recommendations`, `audit_logs`.

**AI:** Google Gemini (via `google-generativeai`) is used for the natural-language AI assistant. Seven purpose-built ML models handle the structured reconnaissance pipeline.

---

## Project Structure

```
Recon-X-main/
├── app.py                          # Flask entry point, blueprint registration, global auth
├── requirements.txt
│
├── config/
│   └── database.py                 # MongoDB connection + DummyCollection fallback
│
├── controllers/
│   ├── view_controller.py          # Page rendering routes
│   ├── auth_controller.py          # Login, signup, OTP password reset
│   ├── scan_controller.py          # Scan orchestrator (calls all models)
│   ├── report_controller.py        # Report data, PDF export, recommendations
│   ├── admin_controller.py         # User management, audit log viewer
│   └── ai_controller.py            # AI assistant endpoints
│
├── middlewares/
│   ├── auth_middleware.py          # @login_required decorator
│   └── admin_middleware.py         # @admin_required decorator
│
├── models/
│   ├── model1.py                   # Subdomain discovery + clustering
│   ├── model2.py                   # Port scanning + service detection
│   ├── model3.py                   # Technology fingerprinting + CVE mapping
│   ├── model4.py                   # HTTP anomaly detection (Isolation Forest)
│   ├── model5.py                   # Exploitation strategy generator (Q-Learning)
│   ├── model6_vulnerability_risk.py # Vulnerability risk scoring (XGBoost)
│   ├── model7_recommendation_engine.py # NLP remediation recommendations
│   └── ai_port_service/            # AI-based port service classifier
│       ├── feature_extraction.py
│       ├── model_inference.py
│       ├── model_training.py
│       └── data_processing.py
│
├── utils/
│   ├── ai_security_assistant.py    # Rule-based + Gemini AI analysis
│   ├── audit_logger.py             # HMAC-signed tamper-resistant audit log
│   ├── domain_validator.py         # Domain validation and normalization
│   ├── gemini_service.py           # Google Gemini API wrapper
│   ├── http_collector.py           # HTTP feature extraction
│   ├── json_utils.py               # MongoDB → JSON serialization
│   ├── logger.py                   # Centralized logging setup
│   ├── nvd_api_tool.py             # NVD API client for CVE lookups
│   ├── report_generator.py         # HTML + PDF report rendering
│   ├── seed_admin.py               # Admin user seeder
│   ├── ssrf_protection.py          # SSRF target validation
│   ├── strategy_stats.py           # Attack strategy statistics builder
│   ├── sublist3r_tool.py           # Sublist3r wrapper (async-safe)
│   ├── tech_fingerprint_tool.py    # Header + Nmap tech fingerprinting
│   ├── traffic_collector.py        # Scapy network traffic capture
│   └── whatweb_tool.py             # WhatWeb technology scanner wrapper
│
├── views/                          # Jinja2 HTML templates
├── static/js/                      # Frontend JavaScript modules
├── training/                       # Standalone model training scripts
├── scripts/                        # Utility scripts (e.g., train_model6)
└── tests/                          # Test suite
```

---

## The AI/ML Pipeline

When a user submits a domain for scanning, `scan_controller.py` runs the following models in sequence:

### Model 1 — Subdomain & Asset Discovery
**File:** [models/model1.py](models/model1.py)

**Approach:** Rule-based discovery + unsupervised clustering.

- Runs **Sublist3r** (via `utils/sublist3r_tool.py`) to enumerate subdomains from public sources.
- Resolves discovered subdomains to IP addresses using parallel DNS lookups (`ThreadPoolExecutor`).
- Performs HTTP liveness checks to identify live vs. dead hosts.
- Clusters subdomains using unsupervised methods (by IP proximity / naming patterns).
- Passes live IPs to Model 2 for port scanning.

### Model 2 — Port Scanning & Service Detection
**File:** [models/model2.py](models/model2.py)

**Approach:** Deterministic (Nmap) + optional ML risk scoring.

- Scans a default set of 16 well-known ports (80, 443, 22, 3306, 27017, etc.) using **python-nmap**.
- Parallel scanning via `ThreadPoolExecutor` across multiple IPs.
- Service identification is deterministic (Nmap banner grabbing). ML (`ai_port_service/`) is used only for post-hoc risk scoring, not identification.
- Calls `analyze_port_security()` to flag risky open ports.

### Model 3 — Technology Fingerprinting & CVE Mapping
**File:** [models/model3.py](models/model3.py)

**Approach:** Supervised ML (Logistic Regression + TF-IDF).

- Collects technology signals from HTTP headers (via `tech_fingerprint_tool.py`) and Nmap banners.
- Uses a trained **TF-IDF + Logistic Regression** model to classify technology stacks.
- Maps detected `technology + version` pairs to known CVEs using the NVD API (`nvd_api_tool.py`) and a local vulnerability database.
- Classifies vulnerability status: `Confirmed`, `Likely`, or `Possible`.
- Pre-trained artifacts stored in `models/artifacts/model3/`.

### Model 4 — HTTP / Traffic Anomaly Detection
**File:** [models/model4.py](models/model4.py)

**Approach:** Unsupervised ML — **Isolation Forest**.

- Collects numerical HTTP features from live hosts (status codes, header entropy, response sizes, redirect counts, etc.) via `utils/http_collector.py`.
- Optionally captures raw network traffic with **Scapy** (`utils/traffic_collector.py`).
- Feeds features into a trained `IsolationForest` (200 estimators, 10% contamination) to detect anomalous HTTP behavior.
- Outputs an anomaly score per host. Scores below threshold are flagged as suspicious.
- Model serialized to `models/artifacts/model4/model4_iforest.pkl`.

### Model 5 — Exploitation Strategy Generator
**File:** [models/model5.py](models/model5.py)

**Approach:** Q-Learning (reinforcement learning) + deterministic CWE/MITRE mapping.

- Accepts confirmed CVEs from Model 3 as input. Returns zero results with no CVEs — no hallucination.
- Maps CVE → CWE → internal attack step vocabulary using `CWE_MAPPING`.
- Uses a **Q-Learning agent** (`QLearningAgent`) to learn optimal sequences of attack steps based on prior transitions. The Q-table is persisted and loaded across runs.
- Queries **Exploit-DB** (`ExploitDBConnector`) to validate whether a public exploit exists, boosting confidence scores.
- Maps each attack step to **MITRE ATT&CK** technique IDs.
- Generates human-readable attack chain narratives with confidence scores.
- Purely defensive/educational — no execution of exploits.

### Model 6 — Vulnerability Risk Scoring
**File:** [models/model6_vulnerability_risk.py](models/model6_vulnerability_risk.py)

**Approach:** Supervised ML — **XGBoost Gradient Boosting** (multi-class).

- Assigns each vulnerability a risk tier: `Low`, `Medium`, `High`, or `Critical`.
- Features include CVSS score, exploit availability, asset exposure, service criticality, and port risk.
- XGBoost classifier: 200 estimators, max depth 6, learning rate 0.05.
- Predictions and scores are stored to the `vulnerability_risk_scores` MongoDB collection.
- Used by both the scan flow and the report view for prioritized display.

### Model 7 — Recommendation Engine
**File:** [models/model7_recommendation_engine.py](models/model7_recommendation_engine.py)

**Approach:** NLP-driven (TF-IDF) + NVD API enrichment.

- Generates tailored remediation guidance per CVE/CWE, enriched with live NVD metadata.
- Produces: risk summary, attack scenario, attack chain, fix recommendations, and a downloadable shell fix script.
- Uses TF-IDF similarity matching across a CWE knowledge base to personalize explanations.
- `prioritize_recommendations()` ranks remediations by CVSS severity.
- Recommendations are saved to MongoDB and served to the report view.

---

## Controllers (API Layer)

| Controller | Blueprint | Responsibility |
|---|---|---|
| [view_controller.py](controllers/view_controller.py) | `views` | Renders all HTML pages |
| [auth_controller.py](controllers/auth_controller.py) | `auth` | Signup, login, logout, OTP-based forgot-password, username/password change |
| [scan_controller.py](controllers/scan_controller.py) | `scan` | Orchestrates the full 6-model scan pipeline for a submitted domain |
| [report_controller.py](controllers/report_controller.py) | `report` | Fetches report data, calls Model 7 for recommendations, exports HTML/PDF |
| [admin_controller.py](controllers/admin_controller.py) | `admin` | CRUD for users, domain allow-lists, role management, audit log access |
| [ai_controller.py](controllers/ai_controller.py) | `ai` | AI assistant endpoints: summarize, score, prioritize, explain biggest risk, free-form Q&A |

---

## Utilities

| Utility | Purpose |
|---|---|
| [gemini_service.py](utils/gemini_service.py) | Google Gemini API wrapper. Primary model: `gemini-flash-latest`, fallback: `gemini-pro-latest` |
| [ai_security_assistant.py](utils/ai_security_assistant.py) | Generates summaries, security scores, fix priorities, and answers using Gemini |
| [audit_logger.py](utils/audit_logger.py) | Appends HMAC-SHA256-signed audit events to MongoDB. Append-only, tamper-detectable |
| [nvd_api_tool.py](utils/nvd_api_tool.py) | Rate-limited NVD REST API client. Supports search by keyword, CPE, and CVE ID |
| [report_generator.py](utils/report_generator.py) | Renders Jinja2 HTML reports and converts to PDF via `pdfkit`/`wkhtmltopdf` |
| [ssrf_protection.py](utils/ssrf_protection.py) | Validates scan targets against private IP ranges to prevent SSRF attacks |
| [domain_validator.py](utils/domain_validator.py) | Validates, normalizes, and checks domains against per-user allow-lists |
| [sublist3r_tool.py](utils/sublist3r_tool.py) | Async-safe Sublist3r wrapper (patches CSRF token and runs in a thread) |
| [whatweb_tool.py](utils/whatweb_tool.py) | Parallel WhatWeb scanner wrapper for technology detection |
| [tech_fingerprint_tool.py](utils/tech_fingerprint_tool.py) | Extracts technologies from HTTP headers and Nmap output |
| [http_collector.py](utils/http_collector.py) | Collects HTTP response features (entropy, sizes, headers) for Model 4 |
| [traffic_collector.py](utils/traffic_collector.py) | Captures live network traffic with Scapy for anomaly detection |

---

## Frontend Views

All views are Jinja2 templates in `views/`. JavaScript in `static/js/` communicates with the Flask API using `fetch`.

| Page | Template | JS Module |
|---|---|---|
| Landing / Index | `views/index.html` | — |
| Login | `views/login.html` | `static/js/login.js` |
| Signup | `views/signup.html` | `static/js/signup.js` |
| Forgot Password | `views/forgot_password.html` | `static/js/forgot_password.js` |
| Dashboard / Home | `views/home.html` | `static/js/dashboard_data.js` |
| Scan | `views/scan.html` | `static/js/scan.js` |
| Report | `views/report.html` | `static/js/report.js` |
| Scan History | `views/history.html` | — |
| AI Assistant | `views/ai_assistant.html` | `static/js/ai_assistant.js` |
| Admin Panel | `views/admin/Admin.html` | `static/js/admin.js` |
| Audit Logs | `views/admin/audit_logs.html` | `static/js/audit_logs.js` |
| Pending Users | `views/admin/pending_users.html` | `static/js/pending_users.js` |
| User Edit | `views/admin/user_edit.html` | — |

---

## Security Design

- **Closed-by-default authentication:** `app.py` registers a `before_request` hook that blocks every unauthenticated request unless the endpoint is on an explicit whitelist. New routes are secure by default.
- **HMAC-signed audit logs:** Every sensitive action (login, scan, report access, user management) is recorded with an HMAC-SHA256 signature. The admin panel can verify integrity.
- **SSRF protection:** `utils/ssrf_protection.py` rejects scan targets resolving to RFC-1918 private addresses or loopback.
- **Rate limiting:** Flask-Limiter (`utils/extensions.py`) caps API call rates to mitigate brute-force and abuse.
- **OTP password reset:** Forgot-password flow sends a time-limited OTP via email; OTPs are stored as bcrypt hashes.
- **Secure session cookies:** `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE="Lax"`, 30-minute lifetime.
- **Role-based access:** `@login_required` and `@admin_required` decorators enforce route-level authorization.
- **Domain allow-lists:** Each user account has a list of domains they are permitted to scan, enforced in `scan_controller.py`.

---

## Setup & Installation

### Prerequisites

- Python 3.9+
- MongoDB (local or Atlas)
- `wkhtmltopdf` (for PDF export — [download here](https://wkhtmltopdf.org/downloads.html))
- `nmap` installed and in PATH
- `whatweb` installed and in PATH (optional)

### Install Python dependencies

```bash
pip install -r requirements.txt
```

### Configure environment variables

Copy `.env.example` to `.env` (or set variables manually — see [Environment Variables](#environment-variables)).

### Seed the admin user

```bash
python -c "from utils.seed_admin import seed_admin; seed_admin()"
```

---

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `SECRET_KEY` | Flask session secret key | `reconx_super_secret_key_123` |
| `MONGO_URI` | MongoDB connection string | `mongodb://localhost:27017/` |
| `GEMINI_API_KEY` | Google Gemini API key | *(required for AI assistant)* |
| `AUDIT_HMAC_SECRET` | Secret for audit log HMAC signing | `reconx_audit_hmac_secret_a7f3b9c2e1d4` |
| `NVD_API_KEY` | NVD API key for higher rate limits | *(optional)* |
| `MAIL_*` | SMTP settings for OTP emails | *(required for password reset)* |

---

## Running the Application

```bash
python app.py
```

The server starts on `http://localhost:5000`. Key routes:

| URL | Description |
|---|---|
| `http://localhost:5000/` | Landing page |
| `http://localhost:5000/login` | Login |
| `http://localhost:5000/signup` | Register |
| `http://localhost:5000/home` | Dashboard |
| `http://localhost:5000/scan` | Submit a domain for scanning |
| `http://localhost:5000/report` | View scan report |
| `http://localhost:5000/admin` | Admin panel (admin role required) |

---

## Training the Models

Pre-trained model artifacts are stored under `models/artifacts/`. To retrain:

```bash
# Model 3 — Technology fingerprinting classifier
python training/train_model3.py

# Model 4 — HTTP anomaly Isolation Forest
python training/train_model4.py

# Model 6 — Vulnerability risk XGBoost
python scripts/train_model6.py
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Web framework | Flask (Python) |
| Database | MongoDB / PyMongo |
| ML — anomaly detection | scikit-learn (Isolation Forest) |
| ML — risk scoring | XGBoost |
| ML — tech fingerprinting | scikit-learn (TF-IDF + Logistic Regression) |
| ML — port service | Custom classifier (`ai_port_service/`) |
| RL — attack strategy | Q-Learning (custom implementation) |
| AI assistant | Google Gemini (`gemini-flash-latest`) |
| Subdomain enumeration | Sublist3r |
| Port scanning | Nmap / python-nmap |
| Tech detection | WhatWeb, HTTP header analysis |
| Traffic capture | Scapy |
| PDF reports | pdfkit + wkhtmltopdf |
| Rate limiting | Flask-Limiter |
| Frontend | Vanilla JS + Fetch API, Chart.js |
