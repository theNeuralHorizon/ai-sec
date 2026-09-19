import unittest

from aegis.dlp import DLPGuard
from aegis.eval import evaluate
from aegis.models import DataLabel


class DLPAndEvaluationTests(unittest.TestCase):
    def test_dlp_redacts_email_and_secret(self) -> None:
        result = DLPGuard().scan_text("Send sk-exampletoken123 to analyst@example.test")
        self.assertEqual(result.labels, frozenset({DataLabel.PII, DataLabel.SECRET}))
        self.assertNotIn("analyst@example.test", result.redacted)
        self.assertNotIn("sk-exampletoken123", result.redacted)
        self.assertEqual(result.match_count, 2)

    def test_context_corpus_and_consequence_metrics(self) -> None:
        report = evaluate()
        self.assertEqual(report["corpus"]["cases"], 8)
        self.assertEqual(report["corpus"]["attacks"], 4)
        self.assertEqual(report["corpus"]["benign"], 4)
        self.assertEqual(report["corpus"]["known_bypasses"], 1)
        self.assertEqual(report["metrics"]["expected_outcome_rate"], 1.0)
        self.assertEqual(report["metrics"]["benign_false_positive_rate"], 0.0)
        self.assertEqual(report["metrics"]["attack_action_block_rate"], 1.0)
        # One of four attacks is the deliberate bypass, so detection is 0.75 by design.
        self.assertEqual(report["metrics"]["attack_detection_rate"], 0.75)


if __name__ == "__main__":
    unittest.main()

