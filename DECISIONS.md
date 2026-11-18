# Decisions

- Dependency Watch code stays outside `dependency-watch-starter-kit/`; scanning reads kit manifests and never edits or runs the kit's change script.
- The kit root is configurable with `KIT_PATH`. Feed and webhook URLs use `FEED_URL` and `WEBHOOK_URL`, defaulting to `http://localhost:7100` and `http://localhost:9900`. SQLite location uses `DATABASE_URL`.
- Python package comparison keys use PEP 503 normalization (lowercase and collapse runs of `.`, `_`, and `-` to `-`). Original names remain available for display.
- Development-only packages are included in scan snapshots and findings, marked `dev_only`, and receive lower deterministic priority than runtime findings.
- npm package instances are keyed by lockfile install path; identical names at different nested `node_modules` paths remain distinct instances.
- Python's `requirements.lock` pins supply resolved versions. Pip-compile `# via` comments are used to derive parent relationships. `requirements-dev.txt` packages are scanned separately and tagged dev-only.
- **Unresolved manifests:** `docs-gen-svc` has no `requirements.lock`. Its `requirements.txt` constraints are stored as declared specifiers with `version = null` and `resolved = false`; no version is guessed and no vulnerability finding is asserted. Matching advisory candidates are recorded as unverified observations.
- Each scan session owns immutable `scan_results` and `dependency_relationships`; later scans append snapshots rather than updating older rows. Findings point at first and latest observations, while observations retain per-scan match state.
- Advisory IDs are upserted. Each changed raw payload is retained in `advisory_revisions`; affected ranges are refreshed from the current advisory. Withdrawn advisories remain stored and their findings are marked resolved with reason `withdrawn`.
- Source severity text is preserved. `MODERATE` is displayed as `Medium`, but source severity is not rewritten and calculated priority is not represented as CVSS.
- FastAPI runs locally with `python -m uvicorn app.main:app --app-dir backend --reload`; database tables and kit services are initialized on application startup.
