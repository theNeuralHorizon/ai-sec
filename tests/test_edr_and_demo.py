from pathlib import Path
import unittest

from aegis.demo import _mandate, run_bypass, run_caught, run_clean
from aegis.edr import SessionMonitor
from aegis.models import ActionClass, Decision, SessionState, ToolRequest, TrustLabel
from aegis.orchestrator import AegisRun


FIXTURES = Path(__file__).parents[1] / "fixtures" / "pages"


class EDRAndDemoTests(unittest.TestCase):
    def test_clean_run_completes_without_containment(self) -> None:
        result = run_clean()
        self.assertEqual(result["action_decision"].decision, Decision.ALLOW)
        self.assertEqual(result["session_state"], SessionState.NORMAL)
        self.assertFalse(result["side_effect_executed"])

    def test_detected_attack_is_blocked_by_provenance_not_a_denylist(self) -> None:
        result = run_caught()
        self.assertGreater(result["context"]["quarantined_count"], 0)
        self.assertEqual(result["action_decision"].decision, Decision.DENY)
        # POL-FLOW-001, not POL-CAP-001: the tool was permitted by the mandate and was
        # stopped because suspicious external content influenced a side effect.
        self.assertEqual(result["action_decision"].rule_id, "POL-FLOW-001")
        self.assertIn("email.send", _mandate().allowed_tools)
        self.assertEqual(result["session_state"], SessionState.CONTAINED)

    def test_detector_bypass_is_still_blocked_and_contained(self) -> None:
        result = run_bypass()
        self.assertEqual(result["context"]["risk_score"], 0)
        self.assertFalse(result["context"]["findings"])
        self.assertEqual(result["context"]["decision"].decision, Decision.ALLOW)
        self.assertEqual(result["action_decision"].decision, Decision.DENY)
        # The gateway found nothing, so the block comes from classifying the payload
        # at egress rather than from any detection of the injected instruction.
        self.assertEqual(result["action_decision"].rule_id, "POL-DATA-001")
        self.assertEqual(result["session_state"], SessionState.CONTAINED)
        self.assertFalse(result["side_effect_executed"])

    def test_taint_is_derived_from_the_page_not_declared_by_the_caller(self) -> None:
        run = AegisRun("taint-1", _mandate())
        run.analyze_html(
            source_id="hidden-css-injection",
            url="https://fixtures.local/hidden-css-injection.html",
            html=(FIXTURES / "hidden-css-injection.html").read_text(encoding="utf-8"),
        )
        # The caller claims the action is untainted; the run knows better.
        request = ToolRequest(
            run_id="taint-1",
            tool_name="email.send",
            action_class=ActionClass.OUTBOUND,
            arguments={"to": "attacker@example.test", "body": "recommendation"},
            destination="attacker@example.test",
            source_trust=TrustLabel.USER_REQUEST,
        )
        decision = run.decide_tool(request)
        self.assertEqual(decision.rule_id, "POL-FLOW-001")
        self.assertEqual(run.context_trust, TrustLabel.SUSPICIOUS_EXTERNAL)
        self.assertTrue(run.context_finding_ids)

    def test_legitimate_email_to_approved_destination_is_not_denied(self) -> None:
        run = AegisRun("legit-1", _mandate())
        run.analyze_html(
            source_id="clean-laptop",
            url="https://fixtures.local/clean-laptop.html",
            html=(FIXTURES / "clean-laptop.html").read_text(encoding="utf-8"),
        )
        decision = run.decide_tool(
            ToolRequest(
                run_id="legit-1",
                tool_name="email.send",
                action_class=ActionClass.OUTBOUND,
                arguments={"to": "demo-user@example.test", "body": "The Northstar 14 is the best value."},
                destination="demo-user@example.test",
            )
        )
        self.assertEqual(decision.decision, Decision.REQUIRE_HUMAN_APPROVAL)
        self.assertEqual(decision.rule_id, "POL-ACT-002")
        self.assertEqual(run.edr.state, SessionState.NORMAL)

    def test_a_later_clean_page_does_not_untaint_the_session(self) -> None:
        run = AegisRun("mono-1", _mandate())
        run.analyze_html(
            source_id="hidden-css-injection",
            url="https://fixtures.local/hidden-css-injection.html",
            html=(FIXTURES / "hidden-css-injection.html").read_text(encoding="utf-8"),
        )
        run.analyze_html(
            source_id="clean-laptop",
            url="https://fixtures.local/clean-laptop.html",
            html=(FIXTURES / "clean-laptop.html").read_text(encoding="utf-8"),
        )
        decision = run.decide_tool(
            ToolRequest(
                run_id="mono-1",
                tool_name="email.send",
                action_class=ActionClass.OUTBOUND,
                arguments={"to": "attacker@example.test", "body": "recommendation"},
                destination="attacker@example.test",
            )
        )
        self.assertEqual(decision.rule_id, "POL-FLOW-001")
        self.assertEqual(run.context_trust, TrustLabel.SUSPICIOUS_EXTERNAL)

    def test_state_machine_records_each_transition(self) -> None:
        result = run_caught()
        transitions = [
            event for event in result["events"] if event.event_type == "session.transition"
        ]
        self.assertEqual(
            [event.outcome for event in transitions],
            [SessionState.SUSPICIOUS, SessionState.CONTAINED],
        )

    def test_only_contained_session_can_be_reviewed(self) -> None:
        monitor = SessionMonitor("run-1")
        with self.assertRaises(ValueError):
            monitor.mark_reviewed()


if __name__ == "__main__":
    unittest.main()

