# Progress

## Backend Core

- Added FastAPI, SQLAlchemy 2, Pydantic settings/schemas, and SQLite configuration under `backend/app/` following the spec's module layout.
- Added service, dependency, per-scan result/relationship, advisory/range/revision, finding/observation/assignment, scan, and activity tables with foreign keys, indexes, and uniqueness constraints.
- Added idempotent import of the eight kit service descriptors and service list/get/create/update endpoints with search, ecosystem, and computed-risk filters.
- Added npm lockfile v3 scanner with direct/transitive edges, nested package instances, and development flags; added Python requirements/lock/dev scanner with pinned versions and pip-compile `# via` parent parsing.
- Unlocked Python declarations stay unresolved; PEP 503 package-name normalization and ecosystem-specific SemVer/PEP 440 range comparisons are implemented.
- Added advisory feed ingestion with payload revision history, idempotent imports, changed/new/withdrawn advisory handling, and scan-driven finding matching. Dev-only findings are marked and lower priority.
- Added scan, dependency-chain, feed-import, findings, and unverified-observation endpoints.
- Test command: `python -m pytest backend\tests -q`
- Latest result: **21 passed**, with one Starlette deprecation warning about the `httpx` test client integration.
- Real feed-1 flow: 8 services, 15 advisories imported, 8 completed scans, 40 package instances, 15 active vulnerable matches/findings, 2 unverified advisory/package observations, and 2 dev-only findings.
- Real feed-2 transition was exercised: 2 new advisories, 2 updated advisories, 13 unchanged advisories; 16 active matches across the subsequent scans, including the new semver advisory and withdrawn urllib3 advisory no longer counted as active. Feed server was restored to feed 1 afterward.
- Full product remains incomplete: no frontend, webhook sending, Docker app stack, remediation workflow endpoints, due-date/assignment actions, production migration system, or final README/REVIEW/transcripts yet.
