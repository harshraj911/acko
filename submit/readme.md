# DEPENDENCY WATCH

> **Know Your Dependencies. Control Your Risks.**  
> Advanced Software Supply Chain Security Platform

---

## 1. Overview

**Dependency Watch** is an enterprise-grade software supply chain security platform that scans multi-language software services, discovers direct and transitive dependencies, identifies known vulnerabilities, evaluates security risks using an explainable prioritization engine, recommends contextual fixes, and tracks vulnerabilities through verified resolution.

The platform is designed to operate seamlessly alongside microservice architectures and external advisory feeds without modifying source repositories or test fixtures.

### Key Capabilities

- **Polyglot Dependency Ingestion:** Recursive npm lockfile v3 parsing preserving exact package paths and nested duplicate versions; Python `requirements.txt` and `requirements.lock` parsing with pip-compile `# via` dependency tree reconstruction.
- **Honest Handling of Unresolved Manifests:** Cleanly handles range-only declarations (`docs-gen-svc`) without fabricating installed package versions or generating false-positive vulnerability findings.
- **OSV Vulnerability Feed Sync:** Continuously ingests Open Source Vulnerability (OSV) records with full payload revision history, handling modified severities, new advisories, and withdrawn records.
- **Precision Range Matching:** Dual-ecosystem comparison engines implementing Semantic Versioning (Node.js) and PEP 440 (Python) with boundary testing across disjoint ranges.
- **Deterministic & Explainable Risk Scoring:** 0–10+ point heuristic incorporating advisory severity, service criticality (Tier 1–3), internet exposure, fix availability, upgrade complexity, and development scoping.
- **One-Band Severity Cap:** Prevents environmental factors from inflating minor vulnerabilities beyond reason.
- **Contextual Fix Guidance:** Recommends exact target versions matching the specific affected range and identifies the direct parent manifest requiring an upgrade for transitive vulnerabilities.
- **Strict Verification Gate:** Findings cannot be closed manually without an automated verification scan confirming the package is no longer vulnerable.
- **Verified Webhook Notifications:** Dispatches structured alerts to external receivers with deduplicated delivery tracking and confirmation checks.
- **Velocitus-Inspired Dark UI:** Deep blacks (`#080808`), dark charcoal panels (`#171717`), vivid crimson accents (`#E50932`), Space Grotesk / JetBrains Mono typography, and real-time SSE scan telemetry.

---

## 2. Tech Stack

### Backend
- **Language & Runtime:** Python 3.11+ / Python 3.13
- **Framework:** FastAPI (asynchronous ASGI framework)
- **ORM & Database:** SQLAlchemy 2.0 with SQLite
- **Validation & Settings:** Pydantic v2 & Pydantic Settings
- **HTTP Client:** HTTPX & Requests
- **Testing:** Pytest

### Frontend
- **Framework & Tooling:** React 18 with Vite and TypeScript
- **Styling:** Custom CSS with Tailwind CSS tokens
- **Data Visualization:** Recharts (Donut, Area, and Bar charts)
- **Icons:** Lucide React
- **Streaming:** Server-Sent Events (EventSource)

### Deployment & Infrastructure
- **Containerization:** Docker & Docker Compose
- **Healthchecks:** HTTP polling probes with automated service dependencies

---

## 3. Project Architecture

```
.
|-- backend/
|   |-- app/
|   |   |-- api/                # REST endpoints and route handlers
|   |   |-- core/               # Configuration settings and environment variables
|   |   |-- database/           # SQLite connection, sessions, and schema migrations
|   |   |-- models/             # SQLAlchemy ORM database models
|   |   |-- schemas/            # Pydantic request/response schemas
|   |   |-- services/
|   |   |   |-- analytics/      # Aggregation metrics for dashboard and charts
|   |   |   |-- overdue/        # Background SLA overdue checker
|   |   |   |-- registry.py     # Service YAML ingestion and metadata management
|   |   |   |-- remediation/    # Upgrade recommendations and parent path analysis
|   |   |   |-- risk_engine/    # Heuristic scoring and severity cap logic
|   |   |   |-- scanner/        # npm v3 & Python lockfile parsers, runner, jobs, SSE
|   |   |   |-- versioning/     # SemVer and PEP 440 comparison engines
|   |   |   |-- vulnerability/  # OSV feed sync, payload revisions, and range matching
|   |   |   `-- webhooks/       # Delivery dispatcher and verification checks
|   |   `-- main.py             # FastAPI entrypoint, lifespan startup, and CORS
|   |-- tests/                  # Pytest test suite (40 unit and integration tests)
|   |-- Dockerfile              # Backend container definition
|   `-- requirements.txt        # Backend Python dependencies
|-- frontend/
|   |-- src/
|   |   |-- components/ui/      # Primitives (Buttons, Badges, Modals, Tables, Skeletons)
|   |   |-- features/
|   |   |   |-- dashboard/      # OverviewPage (metrics, donut chart, risk trend)
|   |   |   |-- scanner/        # ScanCentrePage (real-time SSE progress, scan history)
|   |   |   |-- services/       # ServiceRegistryPage & ServiceDetailPage
|   |   |   `-- shell/          # Navigation bar, AppContext, Logo, Wireframe SVG
|   |   |-- hooks/              # useApi custom hook
|   |   |-- services/           # Typed API client
|   |   |-- types/              # TypeScript interface definitions
|   |   |-- App.tsx             # Application router
|   |   |-- main.tsx            # React DOM mounting
|   |   `-- styles.css          # Design system stylesheet
|   |-- index.html
|   |-- package.json
|   |-- tsconfig.json
|   `-- vite.config.ts
|-- docker-compose.yml          # App stack orchestrated with starter kit services
`-- submit/                     # Submission documentation (plan, progress, readme, design)
```

---

## 4. Getting Started

### Prerequisites
- Python 3.11 or higher
- Node.js 18 or higher with npm
- Docker Desktop (optional, for containerized execution)
- Git (with Git Bash on Windows for change scripts)

---

### Method A: Local Development Setup

#### 1. Backend Setup

From the repository root in PowerShell:

```powershell
# Create and activate a Python virtual environment
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install backend dependencies
python -m pip install -r backend\requirements.txt

# Configure environment variables
$env:KIT_PATH = "C:\Users\Harsh\OneDrive\Desktop\acko\sde-startup-kit-20261118T102601Z-1-001\sde-startup-kit\dependency-watch-starter-kit\dependency-watch-starter-kit"
$env:FEED_URL = "http://localhost:7100"
$env:WEBHOOK_URL = "http://localhost:9900"
$env:DATABASE_URL = "sqlite:///./dependency-watch.db"
$env:AUTO_INITIAL_SCAN = "true"

# Start FastAPI backend server
python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```

The API will initialize the database, import the 8 microservices, sync Feed 1, and launch an initial scan automatically. Interactive OpenAPI documentation is available at `http://localhost:8000/docs`.

#### 2. Frontend Setup

In a separate terminal:

```powershell
cd frontend
npm install
npm run dev
```

The frontend will start at `http://localhost:5173`. It is configured to communicate with the backend at `http://localhost:8000/api` via Vite proxy or direct CORS.

---

### Method B: Docker Compose Execution

To run the entire system (Backend, Vulnerability Feed Server, and Webhook Receiver) using Docker:

```powershell
# Build and launch all services
docker compose up --build -d

# Check service health and logs
docker compose ps
docker compose logs -f backend
```

**Port Bindings:**
- Backend API: `http://localhost:8080` (or configured via `BACKEND_PORT`)
- Vulnerability Feed Server: `http://localhost:7100` (or `FEED_PORT`)
- Webhook Receiver: `http://localhost:9900` (or `WEBHOOK_PORT`)

To stop the containers:

```powershell
docker compose down
```

---

## 5. API Reference

All backend endpoints are prefixed with `/api`.

### Service Registry
- `GET /api/services`: List services with search, ecosystem filter, risk filter, sorting, and pagination.
- `GET /api/services/{id}`: Retrieve detailed metadata for a specific service.
- `POST /api/services`: Register a new microservice.
- `PATCH /api/services/{id}`: Update service metadata (owner, tier, description, internet exposure).

### Dependency & Graph Explorer
- `GET /api/services/{id}/dependencies`: Fetch scanned dependencies for a service (direct/transitive flags, installed versions, scopes, and dependency paths).
- `GET /api/services/{id}/graph`: Retrieve dependency graph nodes and edges with vulnerable chain highlights.
- `GET /api/graph`: Global dependency and service topology graph.

### Scanner Execution
- `POST /api/scans`: Trigger a full batch scan across all registered services (asynchronous, returns `batch_id`).
- `POST /api/services/{id}/scan`: Trigger an on-demand scan for a single service (asynchronous, returns `scan_id`).
- `GET /api/scans`: List historical scan sessions with status, durations, and counts.
- `GET /api/scans/{id}/progress`: Poll progress for an active single-service scan.
- `GET /api/scans/{id}/progress/stream`: Server-Sent Events (SSE) live progress stream.
- `GET /api/scan-batches/{batch_id}/progress/stream`: SSE live progress stream for batch scans.

### Vulnerability Feed & Synchronization
- `POST /api/feed/import`: Fetch and synchronize the latest advisory records from the feed server.
- `POST /api/feed/sync`: Convenience endpoint to sync feed and trigger an incremental scan.

### Findings & Remediation Management
- `GET /api/findings`: Search and filter findings by service, severity, computed priority, status, and dev-only flag.
- `GET /api/findings/{id}`: View finding detail, transparent score breakdown, and contextual fix recommendation.
- `PATCH /api/findings/{id}/status`: Transition finding status (`Open`, `In Progress`, `Resolved`). Requires a verification scan for resolution.
- `PATCH /api/findings/{id}/assignment`: Assign owner and update due date SLA.
- `POST /api/findings/{id}/notes`: Append an operator note to a finding.
- `GET /api/findings/{id}/history`: Chronological audit trail of all status, assignment, and note events.
- `GET /api/findings/overdue`: List findings that have breached their SLA due date.
- `GET /api/findings/unverified`: Surface unverified advisory observations for unlocked declarations (`docs-gen-svc`).

### Security Analytics & Telemetry
- `GET /api/overview`: Aggregated statistics for the dashboard (metric strip, severity distribution, risk trend, top affected services).
- `GET /api/analytics`: Extended telemetry covering resolution velocity, exposure over time, and attention items.
- `GET /api/activity`: Global activity log stream with event filtering.

### Webhook Deliveries
- `GET /api/webhooks/deliveries`: Audit list of outbound webhook alerts and HTTP statuses.
- `GET /api/webhooks/deliveries/{id}/check`: Verifies that the webhook payload was recorded by the receiver endpoint.
- `POST /api/webhooks/test`: Dispatch a test notification.

---

## 6. Testing & Verification Guide

### Automated Test Suite

Execute the 40-test automated suite using Pytest:

```powershell
python -m pytest backend\tests -q
```

### Feed Transition Testing (Feed 1 $\rightarrow$ Feed 2)

1. Ensure the feed server is running on port 7100.
2. Ingest Feed 1:
   ```powershell
   Invoke-RestMethod -Method Post -Uri "http://localhost:7100/control/feed/1"
   Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/feed/import"
   ```
3. Switch to Feed 2:
   ```powershell
   Invoke-RestMethod -Method Post -Uri "http://localhost:7100/control/feed/2"
   Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/feed/import"
   ```
4. Verify changes in the finding list:
   - DW-2026-0009 (`werkzeug`) severity updated to `HIGH`.
   - DW-2026-0010 (`urllib3`) marked `Resolved` with resolution reason `withdrawn`.
   - DW-2026-0016 (`semver`) and DW-2026-0017 (`requests`) added as active findings.
5. Restore feed server to Feed 1:
   ```powershell
   Invoke-RestMethod -Method Post -Uri "http://localhost:7100/control/feed/1"
   ```

### Scripted Change Testing (`scripts/change.sh`)

Test the platform's ability to detect dependency changes and verify resolutions using the starter kit's change script:

```bash
# In Git Bash:
cd sde-startup-kit-20261118T102601Z-1-001/sde-startup-kit/dependency-watch-starter-kit/dependency-watch-starter-kit

# 1. Apply Quote service Axios fix
bash scripts/change.sh fix-quote-axios

# Trigger scan via API or UI and verify the axios findings resolve.

# 2. Revert the fix
bash scripts/change.sh revert-quote-axios

# Rescan and verify the findings reopen.

# 3. Apply Payments JWT fix
bash scripts/change.sh fix-payments-jwt

# Rescan and verify resolution.

# 4. Revert all changes to keep kit untouched
bash scripts/change.sh reset
```

---

## 7. Configuration Reference

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `KIT_PATH` | Inspects workspace | Absolute path to the microservice starter kit directory |
| `FEED_URL` | `http://localhost:7100` | URL of the OSV vulnerability feed server |
| `WEBHOOK_URL` | `http://localhost:9900` | URL of the external webhook receiver |
| `DATABASE_URL` | `sqlite:///./dependency-watch.db` | SQLAlchemy SQLite database connection string |
| `AUTO_INITIAL_SCAN` | `true` | Automatically trigger feed sync and initial scan on startup |
| `CORS_ORIGINS` | `*` | Comma-separated list of allowed CORS origins |
| `OVERDUE_CHECK_SECONDS` | `30` | Interval in seconds for the background overdue finding scheduler |
| `BACKEND_PORT` | `8080` | Host port mapped to backend in Docker Compose |
| `FEED_PORT` | `7100` | Host port mapped to feed server in Docker Compose |
| `WEBHOOK_PORT` | `9900` | Host port mapped to webhook receiver in Docker Compose |
