import json
import threading
import unittest
from pathlib import Path
from urllib.request import urlopen

from aegis.webapp import create_server, scenario_payload


class WebAppTests(unittest.TestCase):
    def test_scenario_payload_is_json_serializable(self) -> None:
        payload = scenario_payload("bypass")
        encoded = json.dumps(payload)
        self.assertIn("POL-DATA-001", encoded)
        self.assertIn("CONTAINED", encoded)

    def test_health_and_dashboard_are_served(self) -> None:
        server = create_server(port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            with urlopen(f"{base}/healthz", timeout=2) as response:
                self.assertEqual(json.load(response), {"status": "ok"})
            with urlopen(base, timeout=2) as response:
                body = response.read()
            self.assertIn(b"Aegis", body)
            self.assertIn(b"Northstar Freight", body)
            with urlopen(f"{base}/styles.css", timeout=2) as response:
                css = response.read().decode("utf-8")
            self.assertIn("#tab-console[hidden], #tab-scenarios[hidden]", css)
            self.assertIn("display: none", css)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


    def test_hidden_tab_rule_is_in_styles(self) -> None:
        css = (Path(__file__).resolve().parents[1] / "ui" / "styles.css").read_text(encoding="utf-8")
        self.assertIn("#tab-console[hidden], #tab-scenarios[hidden] { display: none; }", css)


if __name__ == "__main__":
    unittest.main()

