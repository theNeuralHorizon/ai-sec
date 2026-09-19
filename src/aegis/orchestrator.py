"""Integrated Aegis vertical slice."""

from __future__ import annotations

from dataclasses import replace

from .context_gateway import ContextGateway
from .dlp import DLPGuard
from .edr import SessionMonitor
from .models import ContextEnvelope, DataLabel, PolicyDecision, TaskMandate, ToolRequest, TrustLabel
from .policy import PolicyEngine


TRUST_SEVERITY = {
    TrustLabel.SYSTEM_POLICY: 0,
    TrustLabel.USER_REQUEST: 0,
    TrustLabel.TRUSTED_INTERNAL: 1,
    TrustLabel.EXTERNAL_EVIDENCE: 2,
    TrustLabel.SUSPICIOUS_EXTERNAL: 3,
    TrustLabel.BLOCKED_EXTERNAL: 4,
}


class AegisRun:
    def __init__(self, run_id: str, mandate: TaskMandate) -> None:
        self.run_id = run_id
        self.mandate = mandate
        self.gateway = ContextGateway()
        self.dlp = DLPGuard()
        self.policy = PolicyEngine()
        self.edr = SessionMonitor(run_id)
        self.context_trust = TrustLabel.USER_REQUEST
        self.context_finding_ids: tuple[str, ...] = ()

    def analyze_html(self, *, source_id: str, url: str, html: str) -> tuple[ContextEnvelope, PolicyDecision]:
        envelope = self.gateway.analyze_html(source_id=source_id, url=url, html=html)
        decision = self.policy.evaluate_context(envelope)
        self._absorb_context(envelope)
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
        request = replace(
            request,
            data_labels=frozenset(combined_labels),
            source_trust=self._effective_trust(request.source_trust),
            influenced_by=self._merge_influences(request.influenced_by),
        )
        decision = self.policy.evaluate_tool(self.mandate, request, self.edr.state)
        self.edr.observe_action(request, decision)
        return decision

    def _absorb_context(self, envelope: ContextEnvelope) -> None:
        self.context_trust = self._effective_trust(envelope.source_trust)
        known = set(self.context_finding_ids)
        self.context_finding_ids += tuple(
            finding.finding_id for finding in envelope.findings if finding.finding_id not in known
        )

    def _effective_trust(self, candidate: TrustLabel) -> TrustLabel:
        """Taint is monotonic: the most suspicious label observed in the run wins."""
        return max(self.context_trust, candidate, key=lambda label: TRUST_SEVERITY[label])

    def _merge_influences(self, declared: tuple[str, ...]) -> tuple[str, ...]:
        merged = list(self.context_finding_ids)
        merged.extend(finding_id for finding_id in declared if finding_id not in merged)
        return tuple(merged)
