from pathlib import Path
import unittest

from aegis.context_gateway import ContextGateway
from aegis.models import TrustLabel


FIXTURES = Path(__file__).parents[1] / "fixtures" / "pages"


class ContextGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway = ContextGateway()

    def analyze(self, filename: str):
        return self.gateway.analyze_html(
            source_id=filename,
            url=f"https://fixtures.local/{filename}",
            html=(FIXTURES / filename).read_text(encoding="utf-8"),
        )

    def test_clean_page_preserves_product_evidence(self) -> None:
        envelope = self.analyze("clean-laptop.html")
        evidence = " ".join(segment.text for segment in envelope.evidence)
        self.assertIn("16 GB RAM", evidence)
        self.assertFalse(envelope.findings)
        self.assertEqual(envelope.source_trust, TrustLabel.EXTERNAL_EVIDENCE)

    def test_hidden_instruction_is_quarantined(self) -> None:
        envelope = self.analyze("hidden-css-injection.html")
        self.assertTrue(envelope.quarantined)
        self.assertIn("concealed_instruction", {finding.category for finding in envelope.findings})
        self.assertIn("data_exfiltration", {finding.category for finding in envelope.findings})
        self.assertGreaterEqual(envelope.risk_score, 70)

    def test_quoted_security_example_is_not_treated_as_authority(self) -> None:
        envelope = self.analyze("benign-security-blog.html")
        self.assertFalse(envelope.quarantined)
        self.assertFalse(envelope.findings)

    def test_zero_width_obfuscation_is_reported(self) -> None:
        envelope = self.analyze("unicode-obfuscation.html")
        categories = {finding.category for finding in envelope.findings}
        self.assertIn("invisible_character_obfuscation", categories)
        self.assertIn("concealed_instruction", categories)

    def test_non_http_source_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.gateway.analyze_html(source_id="bad", url="file:///etc/passwd", html="text")


if __name__ == "__main__":
    unittest.main()

