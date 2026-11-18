# Dependency Watch Implementation Plan

## Goal and Priorities

Build a working, explainable security product in six focused build steps (six hours total). The order follows the assignment's section 22: service inventory and architecture first, then scanning and vulnerability matching, risk and findings, product surfaces/integrations, verification and documentation. Functional mandatory requirements take precedence over optional animation and visual refinement. Visual polish is the final work item.

## Inspection Baseline

The supplied kit is under `sde-startup-kit-20261118T102601Z-1-001/sde-startup-kit/dependency-watch-starter-kit/dependency-watch-starter-kit/` in this workspace. Its README documents `docker compose up --build`, feed port 7100, webhook port 9900, and the fact that kit files must remain unchanged. The kit has its own `docker-compose.yml` with only `vulnerability-feed` and `webhook-receiver`.

### Services and files observed

Every service has `service.yaml` with `name`, `owner`, `tier`, `internet_facing`, and `description`. Tier 1 is most critical; tier 3 is least critical.

| Service | Owner; tier; internet-facing | Ecosystem and dependency files |
| --- | --- | --- |
| `payments-svc` | Payments; 1; yes | `package.json`, `package-lock.json` |
| `quote-svc` | Quotes; 2; yes | `package.json`, `package-lock.json` |
| `notifications-svc` | Notifications; 3; no | `package.json`, `package-lock.json` |
| `renewals-svc` | Renewals; 2; no | `package.json`, `package-lock.json` |
| `claims-svc` | Claims; 1; no | `requirements.txt`, `requirements.lock` |
| `policy-svc` | Policy; 1; yes | `requirements.txt`, `requirements.lock` |
| `kyc-svc` | Onboarding; 2; yes | `requirements.txt`, `requirements.lock`, `requirements-dev.txt` |
| `docs-gen-svc` | Documents; 3; no | `requirements.txt`; no lock file present |

The npm lockfiles use lockfile version 3. Python `requirements.lock` files are pip-compile output with exact pins and `# via` relationship comments. `requirements-dev.txt` exists only for KYC and pins `pytest==6.2.4`; it is not represented in `requirements.lock`. The docs generator declares ranges (`Jinja2>=2.10,<3.1`, `pyyaml>=5.1`, `Markdown~=3.3`) without an exact resolved snapshot.

### Advisory feed baseline

Feed 1 contains 15 OSV-shaped mock advisories. Severity is in `database_specific.severity`; the kit uses `CRITICAL`, `HIGH`, `MODERATE`, and `LOW`, not CVSS scores. Fixed versions below are the advisory event boundaries, not recommendations for any package outside that advisory.

| ID | Ecosystem/package | Fixed version(s) | Severity |
| --- | --- | --- | --- |
| DW-2026-0001 | npm `qs` | 6.7.3 and 6.8.3 (separate ranges) | HIGH |
| DW-2026-0002 | npm `jsonwebtoken` | 9.0.0 | HIGH |
| DW-2026-0003 | npm `lodash` | 4.17.21 | HIGH |
| DW-2026-0004 | npm `axios` | 0.21.2 | HIGH |
| DW-2026-0005 | npm `follow-redirects` | 1.14.7 | MODERATE |
| DW-2026-0006 | npm `minimist` | 1.2.6 | CRITICAL |
| DW-2026-0007 | PyPI `pyyaml` | 5.4 | CRITICAL |
| DW-2026-0008 | PyPI `django` | 4.0.8 and 4.1.2 (separate ranges) | HIGH |
| DW-2026-0009 | PyPI `werkzeug` | 2.2.3 | MODERATE in feed 1; HIGH in feed 2 |
| DW-2026-0010 | PyPI `urllib3` | 1.26.5 | MODERATE in feed 1; withdrawn in feed 2 |
| DW-2026-0011 | PyPI `jinja2` | 2.11.3 | MODERATE |
| DW-2026-0012 | PyPI `cryptography` | 39.0.1 | HIGH |
| DW-2026-0013 | PyPI `pytest` | 7.2.0 | LOW |
| DW-2026-0014 | npm `body-parser` | None published | LOW |
| DW-2026-0015 | PyPI `python_multipart` | 0.0.7 | HIGH |

Feed 2 contains 17 records. IDs 0001-0008 and 0011-0015 are unchanged. ID 0009 has modified timestamp and summary updated and severity raised from MODERATE to HIGH (its affected range and fixed version remain the same). ID 0010 remains in the response but has a `withdrawn` timestamp and explanatory details. New ID 0016 is npm `semver`, introduced at 7.0.0, fixed at 7.5.2, HIGH. New ID 0017 is PyPI `requests`, introduced at 2.3.0, fixed at 2.31.0, MODERATE. Feed 2's 0014 remains an open-ended affected range without a fixed event.

### Contract and change script observed

- Feed API: `GET /v1/advisories` (optional ecosystem or `modified_since` filter), `GET /v1/advisories/{id}`, `GET /control/state`, and `POST /control/feed/1` or `/control/feed/2`. Feed server starts on container port 8080, published as host port 7100 by default. Feed 1 is the default.
- Webhook receiver: `POST` to any path accepts JSON or text and returns HTTP 200 with `{"ok":true,"id":N}`; it stores path, parsed body, and arrival timestamp. `GET /api/received` returns stored events, `DELETE /api/received` clears them, and `/` is a simple live viewer. Default host port is 9900. The receiver has no event schema or authentication requirement, so the app should send a consistent JSON payload on a descriptive path and verify delivery using the GET endpoint.
- `scripts/change.sh list` prints documented options. `fix-quote-axios` copies only the quote lockfile, resolving axios 0.21.1 to 0.21.4 and follow-redirects 1.14.0 to 1.14.8 while leaving `package.json` unchanged. Its revert restores that lockfile. `fix-payments-jwt` copies both payments package files, changing jsonwebtoken from 8.5.1 to 9.0.0 and updating the lock graph; its revert restores both. `reset` copies the saved originals for only payments and quote. Although the README describes reset as restoring every service, the script's `original/` data covers only those two services. Do not run this script during planning or implementation because it mutates the evaluator's service inputs.

### Parsing, matching, and lifecycle traps

- `requirements.lock` provides resolved Python package versions and `# via` hints. `requirements.txt` may instead contain exact pins, compatible-release constraints, or open ranges. Do not claim an installed version or vulnerability match from a range-only declaration; record it as unresolved until a lock/snapshot is available.
- Package identity must be ecosystem-aware and canonicalized. Examples present in the kit/feed include `PyYAML` versus `pyyaml`, `Jinja2` versus `jinja2`, and `python-multipart` versus `python_multipart`. Retain the original display name while using a normalized comparison key.
- Scan every package entry in npm `package-lock.json`, including nested paths. `notifications-svc` has both root `node_modules/qs` 6.11.0 (from express) and `node_modules/superagent/node_modules/qs` 6.5.2; they are distinct installed package instances. The latter matches the 0001 vulnerable range while the former does not. Keep instance/path and parent-edge data rather than flattening solely by package name.
- npm lock `dev` metadata exists for payments `lodash`; KYC's `requirements-dev.txt` is outside its production lock. Preserve dependency group/scope so the UI can distinguish runtime and development dependencies without silently omitting the supplied pytest package.
- OSV `SEMVER` and `ECOSYSTEM` ranges need appropriate npm SemVer and Python version parsing, including multiple introduced/fixed event ranges. An advisory with no fixed event (00014) must display no known fix and must not receive an invented upgrade target.
- `MODERATE` is not the UI's `Medium`; map source labels explicitly for display/risk logic and retain the original source severity. Do not label any computed priority as CVSS.
- Withdrawal is not the same thing as a package upgrade or verified resolution. Keep the advisory and history, stop treating withdrawn records as active exposure, and record the lifecycle reason distinctly. Feed updates must be idempotent; do not duplicate advisories or findings.
- A scan after a dependency change must compare package instances and findings with the prior scan. A finding is only resolved after a scan verifies the affected package is no longer in range; UI status changes alone are insufficient.

## Six Build Steps (360 Minutes)

### 1. Foundation, schema, and service inventory (45 min)

- Establish the app at repository root without moving, editing, or copying over the supplied kit. Create the React/Vite/TypeScript frontend, FastAPI/SQLAlchemy backend, SQLite database, and a runnable root app Compose stack.
- Import the eight service descriptors and dependency file locations from the kit; display owner, tier-derived criticality, internet exposure, ecosystem, and scan state. Keep service metadata editable without writing back to kit files.
- Create database initialization and seed/import logic that is safe to run repeatedly. Create a minimal working inventory page and API before building later features.
- Deliverable: app starts, database initializes, all eight services appear, and inventory fields come from the supplied files/database.

### 2. Scanner and dependency history (80 min)

- Parse npm root dependencies and every lockfile package path, preserving direct/transitive edges, dev/runtime scope, and multiple package instances.
- Parse Python `requirements.txt`, `requirements.lock`, and `requirements-dev.txt`. Use exact pins/lock versions for resolved inventory and mark range-only declarations unresolved; use pip-compile comments as relationship evidence only where available.
- Persist scan sessions, package snapshots, edges, and status. Compare successive scans for additions, removals, version changes, and relationship changes. Never fabricate transitive relationships for unpinned manifests.
- Deliverable: scan all eight services, show honest coverage/unknowns, retain snapshots, and report actual scan completion and package counts.

### 3. Feed ingestion, version matching, and findings creation (65 min)

- Import advisories from the live feed endpoint; retain OSV payload/source timestamps and upsert by advisory ID. Parse package ecosystem/name, all affected ranges, fixed events, source severity, and withdrawn timestamp.
- Implement SemVer for npm and PEP 440-compatible comparisons for PyPI, plus canonical package-name matching. Test boundary versions, multiple event ranges, open-ended ranges, nested npm copies, and absent exact Python versions.
- Match resolved dependency instances to active advisories and create/update one finding per service + package instance + advisory identity. Persist withdrawn state without deleting history or presenting it as an active vulnerability.
- Deliverable: changing the feed control endpoint and rescanning/reimporting changes real vulnerability results without duplicates.

### 4. Explainable risk, remediation, and finding workflow (60 min)

- Define a deterministic, documented priority heuristic using source severity, service tier, internet exposure, known fix availability, and complexity only when supported. Store score inputs/reasons; never present the score as CVSS.
- Provide a fix recommendation only when the feed supplies an applicable fixed version. For open-ended/no-fix advisories, say no known fixed version and recommend mitigation/monitoring without inventing a version.
- Implement assignment history, owner, due date, notes, Open/In Progress/Resolved states, overdue calculation, and activity history. Resolve only after a verification scan; retain resolved/reappeared transitions.
- Deliverable: findings list/detail supports the complete lifecycle and explainable priority/remediation.

### 5. Working product surfaces, analytics, and webhook (55 min)

- Connect dashboard metrics to database aggregates: services, resolved package instances, active vulnerabilities/findings, severity, overdue work, recent changes, and latest scans.
- Implement service detail/dependency explorer with graph edges from scanner data, finding/advisory search and filters, and basic analytics/activity views. All navigation/actions must work; omit secondary animation rather than shipping dead controls.
- Send webhook notifications for new critical vulnerabilities, high-priority findings, verified resolutions, and overdue findings to the actual receiver. Use stable event payloads and verify requests via `GET /api/received`.
- Deliverable: a demonstrable end-to-end flow from scan/feed match through finding, notification, and verified resolution.

### 6. Verification, documentation, and final visual pass (55 min)

- Run parser, version/range, matching, idempotency, risk, finding lifecycle/resolution, history, API, and key frontend workflow tests. Exercise feed 1 -> feed 2, including changed severity, new IDs, and withdrawal; exercise both change-script scenarios only in a disposable copy if needed.
- Verify app and kit run concurrently without port conflicts; verify setup with the documented single app command plus the unchanged kit command. Record actual test outcomes and known limitations.
- Complete README, `PROGRESS.md`, `DECISIONS.md`, `REVIEW.md`, API/setup/schema/scoring documentation, and required transcripts as time permits.
- Only after functional checks, apply the required black/charcoal/crimson visual system, responsive layout, typography, and restrained interaction polish. Do not trade working mandatory flows for decorative effects.

## Proposed Folder Structure

```text
.
  MASTER_PROMPT.md
  PLAN.md
  PROGRESS.md
  DECISIONS.md
  README.md
  REVIEW.md
  docker-compose.yml             # app stack only; starter kit remains untouched
  frontend/
    src/
      components/
      layouts/
      pages/
      features/{dashboard,services,dependencies,vulnerabilities,findings,analytics}/
      services/                  # API client
      types/
      styles/
  backend/
    app/
      api/
      core/
      models/
      schemas/
      services/{scanner,vulnerability,versioning,risk_engine,remediation,analytics}/
      database/
    tests/
  tests/                         # cross-component/API workflow tests if needed
  transcripts/
  dependency-watch-starter-kit/  # supplied original; do not alter
```

Keep the implementation modular as shown in the assignment, but avoid premature abstraction within the six-hour limit. The starter-kit directory label above is conceptual; use its actual supplied path and do not relocate it.

## Database Tables

Use SQLite with foreign keys, indexes on common lookups, and uniqueness constraints for idempotent imports. Preserve scans and lifecycle events rather than overwriting historical state.

| Table | Purpose |
| --- | --- |
| `services` | Imported service metadata, editable owner/criticality/exposure fields, and registry identity. Unique service name. |
| `dependencies` | Canonical package identity and display name/ecosystem. Separates a reusable package identity from an installed instance. |
| `dependency_relationships` | Parent-to-child edges scoped to a scan and package paths/instances; supports direct/transitive display and nested duplicate packages. |
| `vulnerability_advisories` | One current record per advisory ID, raw OSV JSON, source severity, modified/withdrawn timestamps, summary, and deduplication. |
| `vulnerability_affected_ranges` | One row per affected package/range/event set, including ecosystem and fixed/introduction boundaries. Supports multiple disjoint ranges and no-fix ranges. |
| `scan_sessions` | Scan start/end/status, service, counts, duration, and errors; provides real progress/latest-scan information. |
| `scan_results` | Per-scan resolved dependency instance, version, path, scope, and package identity; preserves before/after inventory. |
| `findings` | Advisory-to-service/package-instance exposure, status, priority/explanation, detection/resolution timestamps, and active/withdrawn lifecycle. Unique logical finding key prevents repeated imports from duplicating it. |
| `finding_assignments` | Assignment and due-date history rather than losing prior owners when reassigned. |
| `activity_logs` | Chronological service/scan/advisory/finding events and before/after metadata for timelines and analytics. |

## Running Alongside the Unmodified Kit

- Leave the kit's compose file and services untouched. Start its feed and receiver from the kit directory using the README command: `docker compose up --build` (or the documented Podman equivalent). Its default published ports are 7100 and 9900.
- Run the app from the repository root with its own `docker-compose.yml` and `docker compose up --build`. Configure backend feed/webhook base URLs to the kit's published host ports (`host.docker.internal` from Docker Desktop containers; provide the host-gateway mapping for Linux where needed). For host-run development, use `localhost`.
- Keep the two Compose projects separate so app changes cannot alter evaluator fixtures. Document both startup commands and port overrides; ensure app ports do not conflict with 7100/9900.

## Main Risks and Mitigations

- Six hours is short relative to the full spec: implement complete narrow workflows first; make navigation truthful and keep visual extras last.
- Exact installed state is unavailable for `docs-gen-svc`: expose unresolved declarations and do not claim vulnerability-free or vulnerable installed packages there.
- Dependency-name and version-spec differences can create false negatives/positives: normalize names per ecosystem and test SemVer, PEP 440, disjoint ranges, and range boundaries.
- Flattening npm package names loses duplicate instances and paths: key lockfile instances by path within a service scan and preserve parent edges.
- Feed 2 includes changed, added, and withdrawn records: upsert idempotently, retain raw/source history, and distinguish withdrawal from remediation/resolution.
- The `change.sh reset` implementation does not restore all eight services despite README wording, and the script mutates kit fixtures: never invoke against the evaluator's original kit; test only on a disposable copy.
- Source severities are labels, not CVSS scores: preserve exact source wording and document any mapping into the product's four priority bands.
- Rescans can accidentally erase history or prematurely close work: append scan snapshots and resolve findings only after verified non-affected package state.
- Running separate Compose projects requires correct host routing: verify feed reads and webhook delivery from inside the app container on the target OS and document the URLs.
- No Git metadata is present at the current workspace root, so the assignment's requested commit cadence may not be possible until working in a Git repository.
