import asyncio
import json
import os
import sys
from pathlib import Path

from httpx import ASGITransport, AsyncClient
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app


async def main():
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            services = (await client.get("/api/services")).json()
            service_names = {service["id"]: service["name"] for service in services}
            feed = await client.post("/api/feed/import")
            feed.raise_for_status()
            duplicate_feed = await client.post("/api/feed/import")
            duplicate_feed.raise_for_status()
            scans = await client.post("/api/scans")
            scans.raise_for_status()
            findings = await client.get("/api/findings", params={"status": "open"})
            findings.raise_for_status()
            unverified = await client.get("/api/findings/unverified")
            unverified.raise_for_status()
            recommendations = {}
            for finding in findings.json():
                if finding["package_name"] in {"qs", "jsonwebtoken", "body-parser"}:
                    recommendations[finding["package_name"]] = (await client.get(f"/api/findings/{finding['id']}")).json()["recommendation"]
            priorities = []
            for finding in findings.json():
                if finding["package_name"] in {"jsonwebtoken", "qs", "pytest", "body-parser"}:
                    detail = (await client.get(f"/api/findings/{finding['id']}")).json()
                    priorities.append({"service": finding["service_name"], "package": finding["package_name"],
                                       "advisory": finding["advisory_id"], "priority": detail["priority"],
                                       "score": detail["risk_score"], "breakdown": detail["risk_breakdown"]})
            webhook_deliveries = (await client.get("/api/webhooks/deliveries")).json()
            receiver_url = os.environ.get("WEBHOOK_URL", "http://127.0.0.1:9900")
            checks = [
                requests.get(f"{receiver_url}/api/received", timeout=5).json()
                for _ in webhook_deliveries[:1]
            ]
            receiver = requests.get(f"{receiver_url}/api/received", timeout=5)
            receiver.raise_for_status()
            receiver_events = receiver.json()
            receiver_matches = sum(
                1 for event in receiver_events
                if any(event.get("body") == row["payload"] for row in webhook_deliveries)
            )
            print(json.dumps({
                "service_count": len(services),
                "services": [service["name"] for service in services],
                "feed_import": feed.json(),
                "duplicate_feed_import": duplicate_feed.json(),
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
                "sample_priorities": priorities,
                "recommendations": recommendations,
                "webhook_deliveries": [{"event_type": row["event_type"], "success": row["success"],
                                        "response": row["response"]} for row in webhook_deliveries],
                "receiver_check_count": len(checks[0]) if checks else 0,
                "receiver_events": receiver_events,
                "receiver_payload_matches": receiver_matches,
            }, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
