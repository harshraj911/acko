"""Mock vulnerability feed for the Dependency Watch starter kit.

Advisories use the OSV format (https://ossf.github.io/osv-schema/). The IDs are made up for this kit.

GET  /v1/advisories                      all advisories in the current feed
     ?ecosystem=npm|PyPI                 only one ecosystem
     ?modified_since=2026-11-10T00:00:00Z only advisories changed after that time
GET  /v1/advisories/<id>                 one advisory
GET  /control/state                      which feed is being served
POST /control/feed/1                     serve the original feed (the default)
POST /control/feed/2                     serve the updated feed

Do not change this file: the evaluators test against the original kit.
"""
import glob
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PORT = int(os.environ.get("PORT", "8080"))
HERE = os.path.dirname(os.path.abspath(__file__))
FEEDS = {}
for n in (1, 2):
    FEEDS[n] = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(HERE, "feeds", f"feed-{n}", "*.json")))]
state = {"feed": 1}
lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = json.dumps(body, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print(f"feed {self.command} {self.path}", flush=True)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        with lock:
            n = state["feed"]
        advisories = FEEDS[n]
        if u.path == "/control/state":
            return self._send(200, {"feed": n, "advisories": len(advisories)})
        if u.path == "/v1/advisories":
            eco = q.get("ecosystem", [None])[0]
            since = q.get("modified_since", [None])[0]
            out = [a for a in advisories
                   if (not eco or a["affected"][0]["package"]["ecosystem"] == eco)
                   and (not since or a["modified"] > since)]
            return self._send(200, {"feed": n, "count": len(out), "advisories": out})
        if u.path.startswith("/v1/advisories/"):
            aid = u.path.rsplit("/", 1)[1]
            for a in advisories:
                if a["id"] == aid:
                    return self._send(200, a)
            return self._send(404, {"error": f"advisory {aid} not found"})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if u.path in ("/control/feed/1", "/control/feed/2"):
            with lock:
                state["feed"] = int(u.path[-1])
            print(f"now serving feed {state['feed']}", flush=True)
            return self._send(200, {"feed": state["feed"], "advisories": len(FEEDS[state["feed"]])})
        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    print(f"vulnerability feed listening on port {PORT}, serving feed 1", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
