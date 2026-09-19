"""Dependency-free local dashboard and demo API."""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .demo import SCENARIOS, _jsonable


PROJECT_ROOT = Path(__file__).parents[2]
UI_ROOT = PROJECT_ROOT / "ui"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}


def scenario_payload(name: str) -> dict:
    if name not in SCENARIOS:
        raise KeyError(name)
    return _jsonable(SCENARIOS[name]())


class AegisHandler(BaseHTTPRequestHandler):
    server_version = "AegisDemo/0.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlparse(self.path).path
        if path == "/healthz":
            self._send_json({"status": "ok"})
            return
        if path == "/api/scenarios":
            self._send_json({name: scenario_payload(name) for name in SCENARIOS})
            return
        if path.startswith("/api/scenarios/"):
            name = path.rsplit("/", 1)[-1]
            try:
                payload = scenario_payload(name)
            except KeyError:
                self._send_json({"error": "unknown scenario"}, HTTPStatus.NOT_FOUND)
                return
            self._send_json(payload)
            return
        if path in STATIC_FILES:
            filename, content_type = STATIC_FILES[path]
            self._send_bytes((UI_ROOT / filename).read_bytes(), content_type)
            return
        self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def log_message(self, format: str, *args) -> None:
        return

    def _send_json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self._send_bytes(body, "application/json; charset=utf-8", status)

    def _send_bytes(
        self,
        body: bytes,
        content_type: str,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def create_server(host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), AegisHandler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the local Aegis judge dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    server = create_server(args.host, args.port)
    print(f"Aegis dashboard: http://{args.host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

