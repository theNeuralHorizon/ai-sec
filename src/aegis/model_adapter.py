"""Optional local-only adapter for the 3.8B abliterated demo model.

The adapter intentionally asks the model for a short plan, never gives it tool
credentials, and accepts no tool-call syntax from it. The deterministic scope
classifier chooses the capability; policy still authorizes it after planning.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from urllib.parse import urlparse
from urllib.request import Request, urlopen


DEFAULT_MODEL = "marx161-cmd/phi35-mini-disinhibited-abliterated-3.8B"


@dataclass(frozen=True, slots=True)
class ModelObservation:
    model_id: str
    mode: str
    plan: str
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class LocalModelAdapter:
    """Use an OpenAI-compatible *loopback* endpoint when explicitly configured."""

    def __init__(self) -> None:
        self.endpoint = os.environ.get("AEGIS_LOCAL_MODEL_ENDPOINT", "").strip()
        self.model_id = os.environ.get("AEGIS_LOCAL_MODEL_NAME", DEFAULT_MODEL).strip() or DEFAULT_MODEL

    def plan(self, *, prompt: str, intended_tool: str) -> ModelObservation:
        if not self.endpoint:
            return ModelObservation(self.model_id, "deterministic local simulation", f"Plan: use {intended_tool} only after Aegis authorizes it.")
        parsed = urlparse(self.endpoint)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            return ModelObservation(self.model_id, "configuration rejected", "No model call made.", "AEGIS_LOCAL_MODEL_ENDPOINT must be an http loopback address.")
        body = json.dumps({
            "model": self.model_id,
            "temperature": 0,
            "max_tokens": 120,
            "messages": [
                {"role": "system", "content": "You are a supply-chain planning model. Produce a short operational plan only. You have no tools, no credentials, and cannot override policy."},
                {"role": "user", "content": f"Approved task category: {intended_tool}. User request: {prompt}"},
            ],
        }).encode("utf-8")
        try:
            request = Request(self.endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST")
            with urlopen(request, timeout=8) as response:
                payload = json.loads(response.read())
            plan = payload["choices"][0]["message"]["content"].strip()
            return ModelObservation(self.model_id, "local model endpoint", plan[:1_000])
        except (OSError, ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
            return ModelObservation(self.model_id, "local endpoint unavailable; deterministic fallback", f"Plan: use {intended_tool} only after Aegis authorizes it.", str(error))
