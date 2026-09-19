"""Correlated per-session Agent Detection and Response."""

from __future__ import annotations

from dataclasses import dataclass

from .models import (
    ActionClass,
    ContextEnvelope,
    Decision,
    PolicyDecision,
    SecurityEvent,
    SessionState,
    ToolRequest,
    TrustLabel,
)


@dataclass(frozen=True, slots=True)
class EDRAlert:
    rule_id: str
    severity: str
    title: str
    evidence: tuple[str, ...]
    response: str


class SessionMonitor:
    """Maintain a small state machine and causal event chain for one run."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.state = SessionState.NORMAL
        self.events: list[SecurityEvent] = []
        self.alerts: list[EDRAlert] = []
        self._external_context_seen = False
        self._suspicious_context_seen = False
        self._denied_action_count = 0

    def observe_context(self, envelope: ContextEnvelope, decision: PolicyDecision) -> None:
        self._external_context_seen = envelope.source_trust in {
            TrustLabel.EXTERNAL_EVIDENCE,
            TrustLabel.SUSPICIOUS_EXTERNAL,
        }
        self._suspicious_context_seen = bool(envelope.findings or envelope.quarantined)
        self.events.append(
            SecurityEvent(
                run_id=self.run_id,
                event_type="context.admission",
                outcome=decision.decision,
                source_id=envelope.source_id,
                policy_rule_id=decision.rule_id,
                details={
                    "risk_score": envelope.risk_score,
                    "finding_ids": [finding.finding_id for finding in envelope.findings],
                    "source_trust": envelope.source_trust,
                },
            )
        )
        if self._suspicious_context_seen:
            self._advance(SessionState.SUSPICIOUS)
            self.alerts.append(
                EDRAlert(
                    "EDR-CTX-001",
                    "medium",
                    "Suspicious external context influenced the run",
                    tuple(finding.finding_id for finding in envelope.findings),
                    "enhanced_monitoring",
                )
            )

    def observe_action(self, request: ToolRequest, decision: PolicyDecision) -> None:
        self.events.append(
            SecurityEvent(
                run_id=self.run_id,
                event_type="tool.decision",
                outcome=decision.decision,
                tool_name=request.tool_name,
                destination=request.destination,
                policy_rule_id=decision.rule_id,
                details={
                    "action_class": request.action_class,
                    "influenced_by": list(request.influenced_by),
                    "source_trust": request.source_trust,
                },
            )
        )
        if decision.decision is Decision.DENY:
            self._denied_action_count += 1

        side_effect = request.action_class in {
            ActionClass.WRITE,
            ActionClass.OUTBOUND,
            ActionClass.DESTRUCTIVE,
        }
        if decision.decision is Decision.DENY and side_effect and self._external_context_seen:
            self._advance(SessionState.CONTAINED)
            evidence = tuple((*request.influenced_by, decision.rule_id))
            self.alerts.append(
                EDRAlert(
                    "EDR-FLOW-001",
                    "high",
                    "External context was followed by a denied side effect",
                    evidence,
                    "quarantine_session",
                )
            )
        elif self._denied_action_count >= 2:
            self._advance(SessionState.CONTAINED)
            self.alerts.append(
                EDRAlert(
                    "EDR-DENY-001",
                    "high",
                    "Repeated policy denials indicate attempted boundary bypass",
                    (decision.rule_id,),
                    "quarantine_session",
                )
            )

    def mark_reviewed(self) -> None:
        if self.state is not SessionState.CONTAINED:
            raise ValueError("Only a contained session can be marked reviewed")
        self._advance(SessionState.REVIEWED)

    def _advance(self, target: SessionState) -> None:
        rank = {
            SessionState.NORMAL: 0,
            SessionState.SUSPICIOUS: 1,
            SessionState.CONTAINED: 2,
            SessionState.REVIEWED: 3,
        }
        if rank[target] <= rank[self.state]:
            return
        if self.state is SessionState.NORMAL and target in {SessionState.CONTAINED, SessionState.REVIEWED}:
            self.state = SessionState.SUSPICIOUS
        if self.state is SessionState.SUSPICIOUS and target is SessionState.REVIEWED:
            self.state = SessionState.CONTAINED
        self.state = target

