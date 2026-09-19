"""Transparent local evaluation harness for the Aegis vertical slice."""

from __future__ import annotations

import json
from pathlib import Path
from time import perf_counter_ns

from .context_gateway import ContextGateway
from .demo import run_bypass, run_caught
from .models import Decision


PROJECT_ROOT = Path(__file__).parents[2]
PAGES = PROJECT_ROOT / "fixtures" / "pages"
CASES = PROJECT_ROOT / "fixtures" / "expected" / "context_cases.json"


def evaluate() -> dict:
    cases = json.loads(CASES.read_text(encoding="utf-8"))
    gateway = ContextGateway()
    results = []
    latencies_ms = []

    for case in cases:
        html = (PAGES / case["file"]).read_text(encoding="utf-8")
        started = perf_counter_ns()
        envelope = gateway.analyze_html(
            source_id=case["file"],
            url=f"https://fixtures.local/{case['file']}",
            html=html,
        )
        latencies_ms.append((perf_counter_ns() - started) / 1_000_000)
        detected = bool(envelope.findings)
        results.append(
            {
                **case,
                "detected": detected,
                "expectation_met": detected is case["expected_detected"],
                "risk_score": envelope.risk_score,
                "finding_rules": [finding.rule_id for finding in envelope.findings],
            }
        )

    attacks = [result for result in results if result["kind"] == "attack"]
    benign = [result for result in results if result["kind"] == "benign"]
    action_results = [run_caught(), run_bypass()]
    blocked = sum(result["action_decision"].decision is Decision.DENY for result in action_results)

    return {
        "corpus": {
            "cases": len(results),
            "attacks": len(attacks),
            "benign": len(benign),
            "known_bypasses": sum(bool(result.get("known_bypass")) for result in results),
        },
        "metrics": {
            "attack_detection_rate": _ratio(sum(result["detected"] for result in attacks), len(attacks)),
            "benign_false_positive_rate": _ratio(sum(result["detected"] for result in benign), len(benign)),
            "expected_outcome_rate": _ratio(sum(result["expectation_met"] for result in results), len(results)),
            "attack_action_block_rate": _ratio(blocked, len(action_results)),
            "mean_context_scan_ms": round(sum(latencies_ms) / len(latencies_ms), 3),
            "max_context_scan_ms": round(max(latencies_ms), 3),
        },
        "cases": results,
        "disclaimer": "Small synthetic development corpus; these are not production performance claims.",
    }


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def main() -> None:
    print(json.dumps(evaluate(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

