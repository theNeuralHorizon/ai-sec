"""Serve a local GGUF model through the small OpenAI-compatible surface Aegis uses.

This adapter is intentionally loopback-only. It exposes model planning, not
tool access; Aegis remains the capability and policy enforcement point.
"""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock


class LocalGGUFServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], model_path: Path, gpu_layers: int, context: int) -> None:
        from llama_cpp import Llama

        super().__init__(address, LocalGGUFHandler)
        self.model_path = model_path
        self.model = Llama(model_path=str(model_path), n_ctx=context, n_gpu_layers=gpu_layers, verbose=False)
        self.lock = Lock()


class LocalGGUFHandler(BaseHTTPRequestHandler):
    server: LocalGGUFServer
    server_version = "AegisLocalGGUF/0.1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._send({"status": "ok", "model": self.server.model_path.name})
        else:
            self._send({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/chat/completions":
            self._send({"error": "not found"}, HTTPStatus.NOT_FOUND)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 16_384:
                raise ValueError("Request body must be between 1 and 16384 bytes.")
            payload = json.loads(self.rfile.read(length))
            messages = payload.get("messages")
            if not isinstance(messages, list) or not messages:
                raise ValueError("messages must be a non-empty list")
            with self.server.lock:
                response = self.server.model.create_chat_completion(
                    messages=messages,
                    temperature=float(payload.get("temperature", 0)),
                    max_tokens=min(int(payload.get("max_tokens", 120)), 256),
                )
            response["model"] = payload.get("model", self.server.model_path.name)
            self._send(response)
        except (ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError) as error:
            self._send({"error": str(error)}, HTTPStatus.BAD_REQUEST)

    def log_message(self, format: str, *args) -> None:
        return

    def _send(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve a local Q4 GGUF model for Aegis planning")
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--gpu-layers", type=int, default=0, help="0 is CPU-only; requires a CUDA-enabled llama-cpp build for GPU offload.")
    parser.add_argument("--context", type=int, default=2048)
    args = parser.parse_args()
    if not args.model.is_file():
        raise SystemExit(f"Model file not found: {args.model}")
    server = LocalGGUFServer((args.host, args.port), args.model, args.gpu_layers, args.context)
    print(f"Aegis local model: http://{args.host}:{server.server_port}/v1/chat/completions", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
