"""Integrated Aegis vertical slice."""

from __future__ import annotations

from .context_gateway import ContextGateway
from .edr import SessionMonitor
from .models import ContextEnvelope, PolicyDecision, TaskMandate, ToolRequest
from .policy import PolicyEngine


class AegisRun:
    def __init__(self, run_id: str, mandate: TaskMandate) -> None:
        self.run_id = run_id
        self.mandate = mandate
        self.gateway = ContextGateway()
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
        decision = self.policy.evaluate_tool(self.mandate, request, self.edr.state)
        self.edr.observe_action(request, decision)
        return decision

