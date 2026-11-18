# Dependency Watch — Implementation Plan

**Tagline:** Know Your Dependencies. Control Your Risks.  
**System:** Enterprise Software Supply Chain Security Platform

---

## 1. Goal and Priorities

Build a production-quality, explainable software supply chain security platform capable of:
1. Cataloging microservices, metadata, and dependencies across multi-language polyglot codebases (Node.js npm lockfile v3, Python pip requirements / lockfiles).
2. Continuously ingesting vulnerability advisory feeds formatted according to the Open Source Vulnerability (OSV) schema.
3. Precisely matching installed package versions against affected range specifications (SemVer and PEP 440) while handling multi-instance duplicate packages, development scoping, and unresolved range constraints without false positives.
4. Computing a deterministic, fully explainable risk prioritization score with severity caps (preventing environmental inflation without misrepresenting scores as CVSS).
5. Providing contextual remediation advice (exact target version, patch/minor/major classification, and direct parent upgrade guidance).
6. Managing a strict findings lifecycle (Open, In Progress, Resolved) with mandatory verification scans, automatic reopening upon reappearance, and due date SLA tracking with overdue alerts.
7. Dispatching deduplicated webhooks to external notification endpoints and verifying delivery.
8. Exposing a high-contrast, cyberpunk-editorial visual user interface following the Velocitus design aesthetic (deep blacks, dark charcoal, crimson accents, geometric wireframes).

The execution follows a strict 6-stage milestone plan, keeping all supplied starter-kit assets pristine and untouched.

---

## 2. Starter Kit Inspection & Baseline Analysis

The target environment contains 8 microservices located under `sde-startup-kit-20261118T102601Z-1-001/sde-startup-kit/dependency-watch-starter-kit/dependency-watch-starter-kit/`.

### 2.1 Microservice Inventory Baseline

Each service contains a `service.yaml` specifying `name`, `owner`, `tier` (1 = critical, 3 = lowest), `internet_facing` (boolean), and `description`.

| Service | Owner | Tier | Internet-Facing | Ecosystem & Manifests |
| :--- | :--- | :--- | :--- | :--- |
| `payments-svc` | Payments | 1 | Yes | Node.js (`package.json`, `package-lock.json` v3) |
| `quote-svc` | Quotes | 2 | Yes | Node.js (`package.json`, `package-lock.json` v3) |
| `notifications-svc` | Notifications | 3 | No | Node.js (`package.json`, `package-lock.json` v3) |
| `renewals-svc` | Renewals | 2 | No | Node.js (`package.json`, `package-lock.json` v3) |
| `claims-svc` | Claims | 1 | No | Python (`requirements.txt`, `requirements.lock`) |
| `policy-svc` | Policy | 1 | Yes | Python (`requirements.txt`, `requirements.lock`) |
| `kyc-svc` | Onboarding | 2 | Yes | Python (`requirements.txt`, `requirements.lock`, `requirements-dev.txt`) |
| `docs-gen-svc` | Documents | 3 | No | Python (`requirements.txt` only; no lockfile) |

### 2.2 Advisory Feed Baseline

The advisory feed server exposes mock OSV vulnerability records:
- **Feed 1 (Initial):** 15 advisories (DW-2026-0001 through DW-2026-0015).
  - Severities provided as raw string labels: `CRITICAL`, `HIGH`, `MODERATE`, `LOW` (not CVSS numeric scores).
  - Contains disjoint ranges (e.g., DW-2026-0001 qs has two separate fixed events: 6.7.3 and 6.8.3; DW-2026-0008 django has 4.0.8 and 4.1.2).
  - Contains open-ended ranges with no fixed version (DW-2026-0014 body-parser).
- **Feed 2 (Transition/Update):** 17 records.
  - Updates severity of DW-2026-0009 (werkzeug) from MODERATE to HIGH.
  - Withdraws DW-2026-0010 (urllib3) with a `withdrawn` ISO timestamp.
  - Adds DW-2026-0016 (npm semver: introduced 7.0.0, fixed 7.5.2, HIGH).
  - Adds DW-2026-0017 (PyPI requests: introduced 2.3.0, fixed 2.31.0, MODERATE).

### 2.3 External Webhook Receiver Baseline

- Host port 9900 (container port 9000). Accepts any POST payload with JSON or text.
- Returns `{"ok": true, "id": <number>}`.
- Exposes `GET /api/received` to query received event history and `DELETE /api/received` to clear history.

### 2.4 Parsing, Range Matching & Lifecycle Traps

1. **Unresolved Manifests:** `docs-gen-svc` only declares version ranges (`Jinja2>=2.10,<3.1`, `pyyaml>=5.1`, `Markdown~=3.3`). Because no lockfile or snapshot is present, the exact installed version is unknown. The platform must record these as unresolved specifiers (`version = null`, `resolved = false`), must NOT fabricate an installed version, and must NOT register definitive vulnerability findings. Instead, potential advisory matches must be logged as unverified observations.
2. **Package Name Normalization:** PyPI packages use case-insensitive, dash/underscore/dot equivalence (PEP 503 normalization: `pyyaml` vs `PyYAML`, `python-multipart` vs `python_multipart`, `Jinja2` vs `jinja2`).
3. **Duplicate Nested Instances in npm:** Lockfile v3 can install multiple distinct versions of the same package at different nested paths. For example, `notifications-svc` contains root `node_modules/qs` (6.11.0, safe) and nested `node_modules/superagent/node_modules/qs` (6.5.2, vulnerable to DW-2026-0001). The scanner must key packages by install path within each service scan session rather than flattening solely by name.
4. **Development Scope Isolation:** `lodash` in payments has `dev: true`; KYC includes `requirements-dev.txt` (`pytest==6.2.4`). These must be tracked with `dev_only = true` and receive lower risk prioritization.
5. **No CVSS Misrepresentation:** The advisory feed provides qualitative labels (`CRITICAL`, `HIGH`, `MODERATE`, `LOW`). The platform computes a transparent heuristic score (0–10+) mapped to priority bands, while retaining the raw source severity label intact.
6. **Withdrawn Advisories vs Remediation:** When an advisory is withdrawn in Feed 2, its findings are marked resolved with reason `withdrawn` without deleting audit history or falsely crediting code upgrades.
7. **Verification Scan Required for Resolution:** A finding cannot be manually closed if the vulnerable package is still installed. Manual resolution requests trigger an on-demand verification scan and reject the request with HTTP 409 Conflict if still vulnerable.

---

## 3. Architecture & System Modules

```
                    +------------------------------------+
                    |       React / Vite Frontend        |
                    |  (Velocitus Crimson/Black Aesthetic) |
                    +-----------------+------------------+
                                      | REST / SSE Progress
                                      v
                    +------------------------------------+
                    |         FastAPI Core Engine        |
                    +----+---------+------------+----+---+
                         |         |            |    |
          +--------------+   +-----+-----+      |    +-----------------+
          |                  |           |      |                      |
          v                  v           v      v                      v
   +---------------+  +------------+  +-------+---+  +-------------+  +---------------+
   |   Registry    |  |  Scanner   |  | Feed  |   |  | Risk Engine |  | Webhook Dispatch
   | Service YAML  |  | npm v3 &   |  | Engine|   |  | Heuristic & |  | Deduplicated &
   |  Ingestion    |  | Python Lock|  | (OSV) |   |  | Severity Cap|  | Verified (9900)
   +---------------+  +------------+  +-------+---+  +-------------+  +---------------+
                             |               |              |
                             +-------+-------+--------------+
                                     |
                                     v
                       +---------------------------+
                       |      SQLite Database      |
                       |    (SQLAlchemy 2 ORM)     |
                       +---------------------------+
```

### 3.1 Backend Core Modules

1. **`app.api.routes`**: RESTful endpoints for services, dependency graphs, feed ingestion, scan triggers, findings workflow, analytics, and activity timelines.
2. **`app.services.registry`**: Imports `service.yaml` descriptors idempotently; infers ecosystems from manifest filenames; updates metadata.
3. **`app.services.scanner`**:
   - `npm.py`: Recursive lockfile v3 parser capturing dependency paths, direct flags, and dev flags.
   - `python.py`: Regex-based parser for `requirements.txt`, `requirements.lock` with `# via` tree reconstruction, and `requirements-dev.txt`.
   - `runner.py`: Orchestrates multi-service scan execution, records package snapshots, runs finding matchers, and computes scan-to-scan diffs.
   - `jobs.py` & `progress.py`: Asynchronous background scan worker emitting real-time event streams via Server-Sent Events (SSE).
4. **`app.services.vulnerability`**:
   - `importer.py`: Polls/syncs OSV advisory feeds, records raw payload revisions, and normalizes affected ranges.
   - `matcher.py`: Correlates scanned dependencies against active affected ranges using ecosystem-aware version comparison engines.
5. **`app.services.versioning`**:
   - `semver.py`: Clean Semantic Versioning engine for npm supporting `<, <=, >, >=, =` and prerelease identifiers.
   - `pep440.py`: Standard Python PEP 440 version parser supporting epoch, pre/post/dev releases, and complex range sets.
6. **`app.services.risk_engine`**:
   - `scoring.py`: Computes deterministic heuristic scores from severity, tier, exposure, fix availability, and dev scope, with a strict one-band severity cap.
7. **`app.services.remediation`**:
   - `recommendations.py`: Determines nearest safe version within the matching affected range and advises whether direct or transitive parent manifests must be updated.
8. **`app.services.webhooks`**:
   - `delivery.py`: Formats standardized JSON payloads for Critical alerts, deduplicates by composite key, dispatches to port 9900, and verifies receiver ingestion via `GET /api/received`.
9. **`app.services.overdue`**:
   - Background daemon checking finding SLA expiration every 30 seconds and logging overdue notifications.

---

## 4. Database Schema Design

The persistence tier is built on SQLite using SQLAlchemy 2.0 with foreign keys, indexes, and unique constraints.

| Table Name | Primary Purpose | Key Fields & Constraints |
| :--- | :--- | :--- |
| `services` | Service catalog | `id`, `name` (UNIQUE), `owner`, `tier`, `internet_facing`, `ecosystem`, `root_path` |
| `dependencies` | Canonical package catalog | `id`, `name`, `ecosystem`, `canonical_name` (UNIQUE per ecosystem/canonical) |
| `scan_sessions` | Scan audit history | `id`, `service_id`, `status`, `started_at`, `completed_at`, `package_count`, `vulnerability_count`, `error_message` |
| `scan_results` | Immutable per-scan dependency snapshot | `id`, `scan_id`, `dependency_id`, `package_path`, `version`, `specifier`, `resolved`, `direct`, `dev_only`, `manifest_file` |
| `dependency_relationships` | Graph edges between packages | `id`, `scan_id`, `parent_path`, `child_path` |
| `vulnerability_advisories` | Current OSV advisory state | `id`, `advisory_id` (UNIQUE), `summary`, `details`, `source_severity`, `published_at`, `modified_at`, `withdrawn_at`, `raw_payload_json` |
| `vulnerability_affected_ranges`| Disjoint affected range sets | `id`, `advisory_id`, `ecosystem`, `package_name`, `range_type`, `events_json` |
| `advisory_revisions` | Historical feed payload audit | `id`, `advisory_id`, `revision_index`, `raw_payload_json`, `created_at` |
| `findings` | Unique vulnerability exposures | `id`, `logical_key` (UNIQUE), `service_id`, `dependency_id`, `advisory_id`, `package_path`, `installed_version`, `status`, `priority`, `heuristic_score`, `score_breakdown_json`, `due_date`, `assigned_to`, `resolved_at`, `resolution_scan_id` |
| `finding_observations` | Per-scan matching history | `id`, `finding_id`, `scan_id`, `matched_at` |
| `finding_assignments` | Assignment SLA audit trail | `id`, `finding_id`, `assigned_to`, `due_date`, `changed_by`, `assigned_at` |
| `finding_events` | State transition audit log | `id`, `finding_id`, `event_type` (`opened`, `assigned`, `due_date_changed`, `note_added`, `status_changed`, `resolved`, `reopened`), `details_json`, `created_at` |
| `scan_changes` | Chronological scan diffs | `id`, `scan_id`, `service_id`, `change_type` (`package.added`, `package.removed`, `version.changed`, `vulnerability.new`, `vulnerability.resolved`, `vulnerability.reopened`), `details_json`, `created_at` |
| `activity_logs` | Global audit timeline | `id`, `entity_type`, `entity_id`, `event_type`, `service_id`, `details_json`, `created_at` |
| `webhook_deliveries` | Outbound notification tracking | `id`, `delivery_key` (UNIQUE), `event_type`, `endpoint_url`, `request_payload_json`, `response_status_code`, `response_body`, `status`, `attempt_count` |
| `scan_batches` | Multi-service scan coordination | `id`, `batch_id` (UNIQUE), `total_services`, `completed_services`, `status`, `created_at` |

---

## 5. Risk Prioritization & Remediation Engine

### 5.1 Scoring Formula

The product uses an explainable heuristic score:

$$\text{Raw Score} = \text{Severity} + \text{Tier} + \text{Internet Exposure} + \text{Fix Penalty} + \text{Upgrade Complexity} + \text{Dev Deduction}$$

- **Severity Weights:** `CRITICAL` = +8, `HIGH` = +5, `MODERATE` = +3, `LOW` = +1.
- **Service Tier Weights:** Tier 1 = +3, Tier 2 = +2, Tier 3 = +0.
- **Internet Exposure:** Yes = +2, No = +0.
- **Fix Availability:** No published fix in feed = +1, Published fix available = +0.
- **Upgrade Complexity:** Major = +2, Minor = +1, Patch = 0, Unknown = +1.
- **Development Scope:** `dev_only` = -2.
- **Floor:** Scores clamp at a minimum of 0.

### 5.2 Deterministic Priority Bands

- **Critical:** 10+ points
- **High:** 7–9 points
- **Medium:** 3–6 points
- **Low:** 0–2 points

### 5.3 One-Band Severity Cap Mechanism

To prevent an edge-facing Tier 1 service from inflating a genuinely minor `LOW` vulnerability to `CRITICAL`, the priority is strictly capped to at most one band above the raw advisory severity:
- `LOW` source severity $\rightarrow$ Capped at **Medium** (maximum score 6).
- `MODERATE` source severity $\rightarrow$ Capped at **High** (maximum score 9).
- `HIGH` source severity $\rightarrow$ Capped at **Critical** (maximum score 15).
- `CRITICAL` source severity $\rightarrow$ **Critical**.

When a cap is applied, an `Advisory severity cap` item is added to the transparent JSON breakdown detailing the deduction.

---

## 6. Execution Milestones & Plan of Work

### Milestone 1: Environment & Architecture Ingestion
- Initialize project structure outside the starter kit.
- Set up FastAPI application, configuration settings, and database models.
- Register 8 microservices from kit YAML descriptors idempotently.
- Build root Docker Compose configuration running alongside the starter kit.

### Milestone 2: Manifest Scanner & Version Matching
- Implement lockfile v3 recursive parser preserving exact package install paths and direct/transitive edges.
- Implement Python `requirements.txt` and `requirements.lock` parser with `# via` parent-child tracking.
- Handle unlocked declarations (`docs-gen-svc`) cleanly as unverified observations.
- Build SemVer and PEP 440 comparison engines with boundary testing.

### Milestone 3: Vulnerability Feed Sync & Finding Detection
- Build OSV feed ingestion pipeline for Feed 1 (15 advisories) and Feed 2 (17 advisories).
- Correlate installed packages against affected range boundaries.
- Implement deduplicated finding creation keyed by `(service, package_path, advisory)`.
- Support advisory withdrawal lifecycle (`resolved: withdrawn`).

### Milestone 4: Risk Scoring, Remediation & Findings Workflow
- Implement deterministic risk heuristic and severity cap with audit breakdown.
- Compute non-invented fix recommendations based only on matching ranges.
- Implement finding assignment, due dates, activity logs, and SLA overdue worker.
- Enforce mandatory scan verification before allowing manual finding resolution.

### Milestone 5: Webhook Dispatch & Verification
- Dispatch standardized webhook payloads for Critical findings to port 9900.
- Implement deduplicated delivery records.
- Verify delivery against the kit's receiver via `GET /api/received`.

### Milestone 6: User Interface & Verification Documentation
- Build high-contrast, responsive React interface styled after the Velocitus visual system.
- Build Dashboard/Overview with live metrics, donut charts, and risk trends.
- Build Service Registry, Service Detail view, and real-time SSE Scan Centre.
- Execute full automated test suite and live scenario tests against the starter kit.
