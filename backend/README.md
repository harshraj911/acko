# Dependency Watch Backend

## Local Setup

From the repository root in PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
$env:KIT_PATH = "C:\absolute\path\to\dependency-watch-starter-kit"
$env:FEED_URL = "http://localhost:7100"
$env:WEBHOOK_URL = "http://localhost:9900"
$env:DATABASE_URL = "sqlite:///./dependency-watch.db"
python -m uvicorn app.main:app --app-dir backend --reload
```

The actual kit path in this workspace is `sde-startup-kit-20261118T102601Z-1-001/sde-startup-kit/dependency-watch-starter-kit/dependency-watch-starter-kit`. `KIT_PATH` must point to that directory (the directory containing `services/` and `feed-server/`). If omitted, the app uses the inspected workspace-relative default. The feed and webhook variables default to `http://localhost:7100` and `http://localhost:9900`. `DATABASE_URL` defaults to a root-level SQLite file.

On startup, the API creates tables and idempotently imports service metadata from each `services/*/service.yaml`. OpenAPI docs are at `http://localhost:8000/docs`.

## Main API

- `GET /api/services?search=&ecosystem=&risk=`
- `GET /api/services/{id}`
- `POST /api/services`, `PATCH /api/services/{id}`
- `POST /api/feed/import`
- `POST /api/scans`, `POST /api/services/{id}/scan`, `GET /api/scans`
- `GET /api/services/{id}/dependencies?scan_id=`
- `GET /api/findings?search=&service_id=&severity=&priority=&status=&dev_only=&withdrawn=&sort=&direction=`
- `GET /api/findings/unverified`

The app does not write to or run `scripts/change.sh` in the starter kit.

## Docker Compose

From the repository root, run `docker compose up --build`. This starts the backend (`http://localhost:8080`), feed (`http://localhost:7100`), and webhook receiver (`http://localhost:9900`). Override host ports with `BACKEND_PORT`, `FEED_PORT`, and `WEBHOOK_PORT`. The kit's `services/` tree is mounted read-only into the API container; SQLite is stored in the named `dependency_watch_data` volume. Compose waits for feed and receiver health before starting the backend. The Compose file leaves a frontend service insertion point for the next step.
