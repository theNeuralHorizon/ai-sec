"""Integrated Aegis vertical slice."""

from __future__ import annotations

from dataclasses import replace

from .context_gateway import ContextGateway
from .dlp import DLPGuard
from .edr import SessionMonitor
from .models import ContextEnvelope, DataLabel, PolicyDecision, TaskMandate, ToolRequest
from .policy import PolicyEngine


class AegisRun:
    def __init__(self, run_id: str, mandate: TaskMandate) -> None:
        self.run_id = run_id
        self.mandate = mandate
        self.gateway = ContextGateway()
        self.dlp = DLPGuard()
        self.policy = PolicyEngine()
        self.edr = SessionMonitor(run_id)

    def analyze_html(self, *, source_id: str, url: str, html: str) -> tuple[ContextEnvelope, PolicyDecision]:
        envelope = self.gateway.analyze_html(source_id=source_id, url=url, html=html)
        decision = self.policy.evaluate_context(envelope)
        self.edr.observe_context(envelope, decision)
        return envelope, decision

    def decide_tool(self, request: ToolRequest) -> PolicyDecision:
        if request.run_id != self.run_id:
            raise ValueError("Tool request run_id does not match the active Aegis run")
        detected_labels = self.dlp.labels_for_value(
            request.arguments,
            ignored_keys={"to", "destination", "url"},
        )
        combined_labels = set(request.data_labels)
        combined_labels.update(detected_labels)
        if len(combined_labels) > 1:
            combined_labels.discard(DataLabel.PUBLIC)
        request = replace(request, data_labels=frozenset(combined_labels))
        decision = self.policy.evaluate_tool(self.mandate, request, self.edr.state)
        self.edr.observe_action(request, decision)
        return decision
