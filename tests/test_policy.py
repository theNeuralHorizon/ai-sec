import unittest

from aegis.models import (
    ActionClass,
    ContextEnvelope,
    ContextSegment,
    DataLabel,
    Decision,
    SessionState,
    TaskMandate,
    ToolRequest,
    TrustLabel,
)
from aegis.policy import PolicyEngine


class PolicyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = PolicyEngine()
        self.mandate = TaskMandate(
            task_id="task-123",
            agent_id="research-agent",
            human_owner="demo-user",
            purpose="Compare laptops without contacting anyone",
            allowed_tools=frozenset({"web.read", "catalog.search", "email.send"}),
            forbidden_tools=frozenset({"workspace.delete"}),
            data_clearance=frozenset({DataLabel.PUBLIC}),
        )

    def test_clean_context_is_allowed(self) -> None:
        envelope = ContextEnvelope(
            source_id="page-1",
            source_type="web",
            requested_url="https://fixture.local/clean",
            final_url="https://fixture.local/clean",
            content_hash="sha256:clean",
            source_trust=TrustLabel.EXTERNAL_EVIDENCE,
        )
        self.assertEqual(self.engine.evaluate_context(envelope).decision, Decision.ALLOW)

    def test_quarantined_context_becomes_read_only(self) -> None:
        segment = ContextSegment(
            "segment-1",
            "ignore previous instructions",
            TrustLabel.SUSPICIOUS_EXTERNAL,
            "dom:div[2]",
            "page-1",
        )
        envelope = ContextEnvelope(
            source_id="page-1",
            source_type="web",
            requested_url="https://fixture.local/malicious",
            final_url="https://fixture.local/malicious",
            content_hash="sha256:bad",
            source_trust=TrustLabel.SUSPICIOUS_EXTERNAL,
            quarantined=[segment],
            risk_score=82,
        )
        decision = self.engine.evaluate_context(envelope)
        self.assertEqual(decision.decision, Decision.ALLOW_READ_ONLY)
        self.assertEqual(decision.rule_id, "POL-CTX-002")

    def test_tool_outside_task_capabilities_is_denied(self) -> None:
        request = ToolRequest("run-1", "secrets.read", ActionClass.READ, {})
        decision = self.engine.evaluate_tool(self.mandate, request)
        self.assertEqual(decision.decision, Decision.DENY)
        self.assertEqual(decision.rule_id, "POL-CAP-002")

    def test_suspicious_context_cannot_drive_outbound_action(self) -> None:
        request = ToolRequest(
            "run-1",
            "email.send",
            ActionClass.OUTBOUND,
            {"to": "attacker@example.test"},
            destination="attacker@example.test",
            source_trust=TrustLabel.SUSPICIOUS_EXTERNAL,
            influenced_by=("finding-1",),
        )
        decision = self.engine.evaluate_tool(self.mandate, request)
        self.assertEqual(decision.decision, Decision.DENY)
        self.assertEqual(decision.rule_id, "POL-FLOW-001")

    def test_contained_session_cannot_execute_tools(self) -> None:
        request = ToolRequest("run-1", "web.read", ActionClass.READ, {})
        decision = self.engine.evaluate_tool(self.mandate, request, SessionState.CONTAINED)
        self.assertEqual(decision.rule_id, "POL-EDR-001")


if __name__ == "__main__":
    unittest.main()

