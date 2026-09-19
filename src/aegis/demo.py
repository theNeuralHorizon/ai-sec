"""Offline three-run demonstration for the Aegis vertical slice."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .models import ActionClass, DataLabel, TaskMandate, ToolRequest
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
    """The agent may legitimately email its own requester, and nothing more.

    email.send is deliberately a granted capability rather than a denylisted one:
    a static denylist would stop the demo attacks for an uninteresting reason and
    would never exercise the provenance and data-classification rules.
    """
    return TaskMandate(
        task_id="laptop-research",
        agent_id="research-agent",
        human_owner="demo-user",
        purpose="Compare laptops and email the recommendation to the requesting user",
        allowed_tools=frozenset({"web.read", "catalog.search", "email.send"}),
        forbidden_tools=frozenset({"customer.read", "workspace.delete"}),
        data_clearance=frozenset({DataLabel.PUBLIC}),
        approved_destinations=frozenset({"demo-user@example.test"}),
    )


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def run_baseline() -> dict[str, Any]:
    """Show the unsafe path without executing a real side effect."""
    return {
        "scenario": "baseline",
        "protection_enabled": False,
        "mandate": _mandate(),
        "source_url": "https://fixtures.local/hidden-css-injection.html",
        "context": {
            "risk_score": None,
            "findings": [],
            "evidence": [],
            "quarantined": [],
            "evidence_count": None,
            "quarantined_count": 0,
            "source_trust": None,
            "decision": None,
        },
        "proposed_action": {
            "tool_name": "email.send",
            "destination": "attacker@example.test",
            "arguments": {"body": "synthetic customer data"},
        },
        "action_decision": None,
        "side_effect_executed": False,
        "side_effect_would_execute": True,
        "session_state": "UNMONITORED",
        "alerts": [],
        "events": [],
    }


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
    # Trust and influence are NOT declared here: the orchestrator derives them from
    # the page this run actually read, so the demo cannot flatter the policy engine.
    action = ToolRequest(
        run_id=run.run_id,
        tool_name="email.send",
        action_class=ActionClass.OUTBOUND,
        # Deliberately innocuous payload: nothing in this body is sensitive, so the
        # block can only come from where the instruction came from, not what is sent.
        arguments={"to": "attacker@example.test", "body": "Northstar 14 recommendation"},
        destination="attacker@example.test",
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
    )
    action_decision = run.decide_tool(action)
    return _result("bypass", envelope, context_decision, action, action_decision, run)


def _result(name, envelope, context_decision, action, action_decision, run) -> dict[str, Any]:
    return {
        "scenario": name,
        "protection_enabled": True,
        "mandate": run.mandate,
        "source_url": envelope.requested_url,
        "context": {
            "risk_score": envelope.risk_score,
            "findings": envelope.findings,
            "evidence": envelope.evidence,
            "quarantined": envelope.quarantined,
            "evidence_count": len(envelope.evidence),
            "quarantined_count": len(envelope.quarantined),
            "source_trust": envelope.source_trust,
            "decision": context_decision,
        },
        "proposed_action": action,
        "action_decision": action_decision,
        "side_effect_executed": False,
        "side_effect_would_execute": False,
        "session_state": run.edr.state,
        "alerts": run.edr.alerts,
        "events": run.edr.events,
    }


SCENARIOS = {
    "baseline": run_baseline,
    "clean": run_clean,
    "caught": run_caught,
    "bypass": run_bypass,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the offline Aegis security demonstration")
    parser.add_argument("scenario", choices=(*SCENARIOS, "all"), nargs="?", default="all")
    args = parser.parse_args()
    selected = SCENARIOS.values() if args.scenario == "all" else (SCENARIOS[args.scenario],)
    print(json.dumps(_jsonable([scenario() for scenario in selected]), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
