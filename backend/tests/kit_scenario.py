import asyncio
import json
import sys
from pathlib import Path

from httpx import ASGITransport, AsyncClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app


async def main(service_name: str):
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            service = next(item for item in (await client.get("/api/services")).json() if item["name"] == service_name)
            before = (await client.get("/api/scans", params={"service_id": service["id"]})).json()
            scan_response = await client.post(f"/api/services/{service['id']}/scan")
            scan_response.raise_for_status()
            scan = scan_response.json()
            changes = (await client.get(f"/api/services/{service['id']}/changes")).json()
            relevant = [item for item in changes if item["scan_id"] == scan["id"]]
            edges = (await client.get(f"/api/services/{service['id']}/dependencies", params={"scan_id": scan["id"]})).json()
            findings = (await client.get("/api/findings", params={"service_id": service["id"], "status": "open"})).json()
            print(json.dumps({
                "service": service_name,
                "previous_scan_id": before[0]["id"] if before else None,
                "scan_id": scan["id"],
                "package_count": scan["package_count"],
                "vulnerable_matches": scan["vulnerable_count"],
                "changes": [{"type": item["change_type"], "entity": item["entity_key"],
                             "before": item["before"], "after": item["after"]} for item in relevant],
                "dependencies": [{"package": item["name"], "version": item["version"], "direct": item["direct"]}
                                 for item in edges],
                "open_findings": [{"id": item["id"], "advisory": item["advisory_id"],
                                   "package": item["package_name"], "version": item["installed_version"]}
                                  for item in findings],
            }, indent=2))


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
