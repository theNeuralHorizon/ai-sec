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
        # Accumulate, never overwrite: reading a clean page after a hostile one does not
        # untaint the session, and an attacker would otherwise just append a benign fetch.
        self._external_context_seen = self._external_context_seen or envelope.source_trust in {
            TrustLabel.EXTERNAL_EVIDENCE,
            TrustLabel.SUSPICIOUS_EXTERNAL,
        }
        self._suspicious_context_seen = self._suspicious_context_seen or bool(
            envelope.findings or envelope.quarantined
        )
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
        elif side_effect and self._suspicious_context_seen:
            self._advance(SessionState.SUSPICIOUS)
            self.alerts.append(
                EDRAlert(
                    "EDR-FLOW-002",
                    "medium",
                    "A side effect was attempted after suspicious context was admitted",
                    (decision.rule_id,),
                    "require_human_review",
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
        """Walk the state machine one step at a time, recording every transition.

        Stepping matters for the investigation timeline: jumping straight to CONTAINED
        loses the fact that the session passed through SUSPICIOUS and why.
        """
        order = (
            SessionState.NORMAL,
            SessionState.SUSPICIOUS,
            SessionState.CONTAINED,
            SessionState.REVIEWED,
        )
        current = order.index(self.state)
        goal = order.index(target)
        if goal <= current:
            return
        for rank in range(current + 1, goal + 1):
            previous, self.state = self.state, order[rank]
            self.events.append(
                SecurityEvent(
                    run_id=self.run_id,
                    event_type="session.transition",
                    outcome=self.state,
                    details={"from": previous},
                )
            )

