import unittest

from aegis.demo import run_bypass, run_caught, run_clean
from aegis.edr import SessionMonitor
from aegis.models import Decision, SessionState


class EDRAndDemoTests(unittest.TestCase):
    def test_clean_run_completes_without_containment(self) -> None:
        result = run_clean()
        self.assertEqual(result["action_decision"].decision, Decision.ALLOW)
        self.assertEqual(result["session_state"], SessionState.NORMAL)
        self.assertFalse(result["side_effect_executed"])

    def test_detected_attack_is_quarantined_and_contained(self) -> None:
        result = run_caught()
        self.assertGreater(result["context"]["quarantined_count"], 0)
        self.assertEqual(result["action_decision"].decision, Decision.DENY)
        self.assertEqual(result["session_state"], SessionState.CONTAINED)

    def test_detector_bypass_is_still_blocked_and_contained(self) -> None:
        result = run_bypass()
        self.assertEqual(result["context"]["risk_score"], 0)
        self.assertFalse(result["context"]["findings"])
        self.assertEqual(result["context"]["decision"].decision, Decision.ALLOW)
        self.assertEqual(result["action_decision"].decision, Decision.DENY)
        self.assertEqual(result["action_decision"].rule_id, "POL-CAP-001")
        self.assertEqual(result["session_state"], SessionState.CONTAINED)
        self.assertFalse(result["side_effect_executed"])

    def test_only_contained_session_can_be_reviewed(self) -> None:
        monitor = SessionMonitor("run-1")
        with self.assertRaises(ValueError):
            monitor.mark_reviewed()


if __name__ == "__main__":
    unittest.main()

