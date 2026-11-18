# Progress

## Backend Core

- Added FastAPI, SQLAlchemy 2, Pydantic settings/schemas, and SQLite configuration under `backend/app/` following the spec's module layout.
- Added service, dependency, per-scan result/relationship, advisory/range/revision, finding/observation/assignment, scan, and activity tables with foreign keys, indexes, and uniqueness constraints.
- Added idempotent import of the eight kit service descriptors and service list/get/create/update endpoints with search, ecosystem, and computed-risk filters.
- Added npm lockfile v3 scanner with direct/transitive edges, nested package instances, and development flags; added Python requirements/lock/dev scanner with pinned versions and pip-compile `# via` parent parsing.
- Unlocked Python declarations stay unresolved; PEP 503 package-name normalization and ecosystem-specific SemVer/PEP 440 range comparisons are implemented.
- Added advisory feed ingestion with payload revision history, idempotent imports, changed/new/withdrawn advisory handling, and scan-driven finding matching. Dev-only findings are marked and lower priority.
- Added scan, dependency-chain, feed-import, findings, and unverified-observation endpoints.
- Added centralized explainable risk weights, score/priority/breakdown, and priority-based default due dates. Finding API displays the heuristic breakdown and applicable recommendation.
- Added matching-range-only fix recommendations, patch/minor/major upgrade classification, and direct/transitive parent guidance from scanner relationship paths.
- Added finding assignment, status, due-date, notes, history, overdue and verified-resolution APIs; resolved findings reopen with a reappearance event. Scan history records immutable snapshot diffs and has a per-service chronological timeline API.
- Added filtered activity events and deduplicated webhook delivery attempts with real response capture and receiver GET verification. Real receiver accepted notifications and was cleared after the final end-to-end run.
- Added additive SQLite column migrations for databases created by the earlier backend schema.
- Test command: `python -m pytest backend\tests -q`
- Latest result: **34 passed**, with one Starlette deprecation warning about the `httpx` test client integration.
- Real feed-1 flow: 8 services, 15 advisories imported, 8 completed scans, 40 package instances, 15 active vulnerable matches/findings, 2 unverified advisory/package observations, and 2 dev-only findings.
- Real feed-2 transition was exercised: 2 new advisories, 2 updated advisories, 13 unchanged advisories; 16 active matches across the subsequent scans, including the new semver advisory and withdrawn urllib3 advisory no longer counted as active. Feed server was restored to feed 1 afterward.
- Full product remains incomplete: no frontend, webhook sending, Docker app stack, remediation workflow endpoints, due-date/assignment actions, production migration system, or final README/REVIEW/transcripts yet.
- Scripted change detection was run through `C:\Program Files\Git\bin\bash.exe` and `bash scripts/change.sh`: quote fix changed axios 0.21.1->0.21.4 and follow-redirects 1.14.0->1.14.8, resolved two findings; revert restored both versions and reopened both findings. Payments JWT fix changed jsonwebtoken 8.5.1->9.0.0, semver 5.7.1->7.5.4 and added lru-cache/yallist; revert reversed those changes and reopened the JWT finding. `bash scripts/change.sh reset` ran at the end. `git status` and `git diff` show no changes inside the starter kit.
- Latest live feed-1 run: 8 services, 15 advisories imported; duplicate import reported 15 unchanged; 40 packages; 15 active findings (2 dev-only); 2 unresolved docs-gen packages yielded 2 advisory matches and 3 unverified declaration rows. Real receiver returned `{ok:true,id:n}` for each of 13 notifications; `GET /api/received` contained all 13 exact payloads. Receiver was cleared afterward and feed control is back at feed 1.
- Main remaining product scope is frontend, app Compose packaging, review/submission docs, transcripts, and broader API integration/security hardening. Current version logs note the real receiver can fail through the `localhost` alias on this host; use `WEBHOOK_URL=http://127.0.0.1:9900` for local host execution here.
