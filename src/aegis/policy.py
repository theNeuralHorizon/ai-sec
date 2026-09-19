"""Deterministic policy evaluation for context and tool boundaries."""

from __future__ import annotations

from .models import (
    ActionClass,
    ContextEnvelope,
    DataLabel,
    Decision,
    PolicyDecision,
    SessionState,
    TaskMandate,
    ToolRequest,
    TrustLabel,
)


SENSITIVE_LABELS = frozenset({DataLabel.CONFIDENTIAL, DataLabel.PII, DataLabel.SECRET})


class PolicyEngine:
    """Small, explicit policy engine with stable rule identifiers."""

    version = "aegis-policy-0.1"

    def evaluate_context(self, envelope: ContextEnvelope) -> PolicyDecision:
        if envelope.source_trust is TrustLabel.BLOCKED_EXTERNAL or envelope.risk_score >= 95:
            return self._decision(
                Decision.DENY,
                "POL-CTX-001",
                "The source is blocked or exceeds the critical context-risk threshold.",
            )
        if envelope.quarantined or envelope.risk_score >= 70:
            return self._decision(
                Decision.ALLOW_READ_ONLY,
                "POL-CTX-002",
                "Suspicious content is quarantined; only labeled evidence may be used read-only.",
            )
        if envelope.data_labels & SENSITIVE_LABELS:
            return self._decision(
                Decision.ALLOW_WITH_REDACTION,
                "POL-CTX-003",
                "Sensitive ingress data must be redacted before external model use or logging.",
            )
        return self._decision(
            Decision.ALLOW,
            "POL-CTX-000",
            "No context-admission rule was violated.",
        )

    def evaluate_tool(
        self,
        mandate: TaskMandate,
        request: ToolRequest,
        session_state: SessionState = SessionState.NORMAL,
    ) -> PolicyDecision:
        if session_state is SessionState.CONTAINED:
            return self._decision(
                Decision.DENY,
                "POL-EDR-001",
                "Contained sessions cannot execute tools.",
            )
        if request.tool_name in mandate.forbidden_tools:
            return self._decision(
                Decision.DENY,
                "POL-CAP-001",
                "The requested tool is explicitly forbidden by the task mandate.",
            )
        if request.tool_name not in mandate.allowed_tools:
            return self._decision(
                Decision.DENY,
                "POL-CAP-002",
                "The requested tool is outside the task-scoped capability set.",
            )
        if not request.data_labels.issubset(mandate.data_clearance):
            return self._decision(
                Decision.DENY,
                "POL-DATA-001",
                "The agent lacks clearance for one or more data labels.",
            )
        if request.data_labels & SENSITIVE_LABELS and request.action_class is ActionClass.OUTBOUND:
            if request.destination not in mandate.approved_destinations:
                return self._decision(
                    Decision.DENY,
                    "POL-DLP-001",
                    "Sensitive data cannot flow to an unapproved external destination.",
                )
        if (
            request.source_trust is TrustLabel.SUSPICIOUS_EXTERNAL
            and request.action_class in {ActionClass.WRITE, ActionClass.OUTBOUND, ActionClass.DESTRUCTIVE}
        ):
            return self._decision(
                Decision.DENY,
                "POL-FLOW-001",
                "Suspicious external content cannot influence a side-effecting action.",
            )
        if (
            request.source_trust in {TrustLabel.EXTERNAL_EVIDENCE, TrustLabel.SUSPICIOUS_EXTERNAL}
            and request.action_class is ActionClass.DESTRUCTIVE
        ):
            return self._decision(
                Decision.DENY,
                "POL-ACT-001",
                "Untrusted external content cannot authorize a destructive action.",
            )
        if request.action_class in {ActionClass.WRITE, ActionClass.OUTBOUND} and not request.approval_granted:
            return self._decision(
                Decision.REQUIRE_HUMAN_APPROVAL,
                "POL-ACT-002",
                "A permitted side effect requires explicit transaction approval.",
            )
        return self._decision(
            Decision.ALLOW,
            "POL-ALLOW-000",
            "The request satisfies the task mandate and action policy.",
        )

    def _decision(self, decision: Decision, rule_id: str, reason: str) -> PolicyDecision:
        return PolicyDecision(decision, rule_id, reason, self.version)

