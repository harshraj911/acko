import asyncio
import json
import sys
from pathlib import Path

from httpx import ASGITransport, AsyncClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app


async def main():
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            services = (await client.get("/api/services")).json()
            service_names = {service["id"]: service["name"] for service in services}
            feed = await client.post("/api/feed/import")
            feed.raise_for_status()
            scans = await client.post("/api/scans")
            scans.raise_for_status()
            findings = await client.get("/api/findings", params={"status": "open"})
            findings.raise_for_status()
            unverified = await client.get("/api/findings/unverified")
            unverified.raise_for_status()
            print(json.dumps({
                "service_count": len(services),
                "services": [service["name"] for service in services],
                "feed_import": feed.json(),
                "scan_count": len(scans.json()),
                "package_count_total": sum(scan["package_count"] for scan in scans.json()),
                "vulnerable_match_total": sum(scan["vulnerable_count"] for scan in scans.json()),
                "unverified_match_total": sum(scan["unverified_count"] for scan in scans.json()),
                "scans": [{
                    "service": service_names[scan["service_id"]],
                    "status": scan["status"],
                    "packages": scan["package_count"],
                    "vulnerable_matches": scan["vulnerable_count"],
                    "unverified_matches": scan["unverified_count"],
                    "error": scan["error"],
                } for scan in scans.json()],
                "open_findings": len(findings.json()),
                "dev_only_findings": sum(1 for finding in findings.json() if finding["dev_only"]),
                "unverified_records": len(unverified.json()),
            }, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
