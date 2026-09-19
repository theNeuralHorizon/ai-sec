"""End-to-end synthetic Northstar Freight agent runtime.

The model adapter is deliberately non-authoritative.  It represents the
requested abliterated 3.8B Phi-3.5 class model in the demo, but Aegis grants
capabilities and runs tools only after deterministic policy checks.
"""

from __future__ import annotations

import re
from dataclasses import asdict
from uuid import uuid4

from .company import FILES, SHIPMENTS, TOOLS, USERS, DemoUser, visible_files_for
from .demo import _jsonable
from .model_adapter import DEFAULT_MODEL, LocalModelAdapter
from .models import ActionClass, DataLabel, Decision, PolicyDecision, TaskMandate, ToolRequest, TrustLabel
from .orchestrator import AegisRun
from .scope import MultiLayerScopeGuard, ScopeVerdict


MODEL_PROFILE = {
    "model_id": DEFAULT_MODEL,
    "parameter_class": "3.8B (4B class)",
    "mode": "deterministic local simulation",
    "boundary": "The model never receives direct tool credentials; Aegis policy authorizes every tool proposal.",
}


class SupplyChainRuntime:
    def __init__(self) -> None:
        self.scope = MultiLayerScopeGuard()
        self.model = LocalModelAdapter()

    def run(self, *, user_id: str, prompt: str, approval_granted: bool = False) -> dict:
        if user_id not in USERS:
            raise ValueError("Unknown synthetic company user")
        user = USERS[user_id]
        run_id = f"northstar-{uuid4().hex[:8]}"
        scope = self.scope.assess(prompt)
        assessment = scope["assessment"]
        trace = [
            {"stage": "identity", "outcome": "BOUND", "detail": f"{user.name} · {user.role}"},
            {"stage": "scope", "outcome": assessment["verdict"], "detail": assessment["reason"]},
        ]
        verdict = ScopeVerdict(assessment["verdict"])
        if verdict is not ScopeVerdict.IN_SCOPE:
            rule_id = "POL-SCOPE-002" if verdict is ScopeVerdict.SENSITIVE_EXFILTRATION else "POL-SCOPE-001"
            decision = PolicyDecision(Decision.DENY, rule_id, assessment["reason"], "aegis-policy-0.2")
            trace.append({"stage": "policy", "outcome": decision.decision.value, "detail": f"{decision.rule_id}: {decision.reason}"})
            return self._result(run_id, user, prompt, scope, trace, None, decision, None, "REFUSED", [])

        tool_name = assessment["intended_tool"]
        assert tool_name is not None
        mandate = self._mandate(user, tool_name)
        run = AegisRun(run_id, mandate)
        observation = self.model.plan(prompt=prompt, intended_tool=tool_name)
        proposed = self._model_proposal(run_id, prompt, tool_name, user, approval_granted)
        trace.append({"stage": "model", "outcome": "PROPOSED", "detail": f"{observation.mode}: {observation.plan}"})
        decision = run.decide_tool(proposed)
        trace.append({"stage": "policy", "outcome": decision.decision.value, "detail": f"{decision.rule_id}: {decision.reason}"})
        tool_result = None
        final = "BLOCKED"
        if decision.decision is Decision.ALLOW:
            tool_result = self._invoke_synthetic_tool(user, proposed)
            final = "COMPLETED"
            trace.append({"stage": "tool", "outcome": "SIMULATED_RESULT", "detail": tool_result["summary"]})
        elif decision.decision is Decision.REQUIRE_HUMAN_APPROVAL:
            final = "AWAITING_APPROVAL"
            trace.append({"stage": "tool", "outcome": "HELD", "detail": "No message is sent; an authorized human must approve this synthetic portal update."})
        result = self._result(run_id, user, prompt, scope, trace, proposed, decision, tool_result, final, _jsonable(run.edr.events), _jsonable(run.edr.alerts), run.edr.state.value)
        result["model_observation"] = observation.to_dict()
        return result

    @staticmethod
    def _mandate(user: DemoUser, intended_tool: str) -> TaskMandate:
        # The passport deliberately carries the user's role-limited capability set,
        # not a model-selected list of tools.
        return TaskMandate(
            task_id=f"northstar-{intended_tool}", agent_id="northstar-ops-agent", human_owner=user.user_id,
            purpose="Search approved company records, look up a shipment, or prepare a portal-only customer update.",
            allowed_tools=user.tools, data_clearance=user.clearance,
            approved_destinations=frozenset({"customer-portal.local"}),
        )

    @staticmethod
    def _model_proposal(run_id: str, prompt: str, tool_name: str, user: DemoUser, approval_granted: bool) -> ToolRequest:
        if tool_name == "shipment.lookup":
            reference = (re.search(r"\bNF-\d{4}\b", prompt, re.I) or ["NF-2048"])[0].upper()
            return ToolRequest(run_id, tool_name, ActionClass.READ, {"reference": reference}, data_labels=frozenset({DataLabel.PII}), source_trust=TrustLabel.USER_REQUEST)
        if tool_name == "customer.notify":
            reference = (re.search(r"\bNF-\d{4}\b", prompt, re.I) or ["NF-2048"])[0].upper()
            return ToolRequest(run_id, tool_name, ActionClass.OUTBOUND,
                               {"reference": reference, "message": "Synthetic delay update prepared for customer portal review."},
                               destination="customer-portal.local", data_labels=frozenset({DataLabel.PII}), source_trust=TrustLabel.USER_REQUEST,
                               approval_granted=approval_granted and user.can_approve_notifications)
        return ToolRequest(run_id, "company.files.search", ActionClass.READ, {"query": prompt}, data_labels=frozenset({DataLabel.INTERNAL}), source_trust=TrustLabel.USER_REQUEST)

    @staticmethod
    def _invoke_synthetic_tool(user: DemoUser, request: ToolRequest) -> dict:
        if request.tool_name == "shipment.lookup":
            record = SHIPMENTS.get(request.arguments["reference"], {"reference": request.arguments["reference"], "status": "No synthetic shipment found"})
            return {"tool": request.tool_name, "summary": f"{record['reference']}: {record['status']}", "data": record}
        if request.tool_name == "company.files.search":
            terms = set(re.findall(r"[a-z]{4,}", request.arguments["query"].lower()))
            hits = [document for document in visible_files_for(user.user_id) if terms & set(re.findall(r"[a-z]{4,}", f"{document.title} {document.summary}".lower()))]
            if not hits:
                hits = list(visible_files_for(user.user_id))[:3]
            documents = [{"title": doc.title, "path": doc.path, "label": doc.label.value, "summary": doc.summary} for doc in hits[:3]]
            return {"tool": request.tool_name, "summary": f"Found {len(documents)} role-authorized document(s).", "documents": documents}
        if request.tool_name == "customer.notify":
            reference = request.arguments["reference"]
            return {
                "tool": request.tool_name,
                "summary": f"Synthetic portal update for {reference} approved and recorded; no message was sent.",
                "data": {"reference": reference, "destination": request.destination, "delivery": "simulated"},
            }
        raise ValueError("Only approved synthetic tools may be invoked")

    @staticmethod
    def _result(run_id, user, prompt, scope, trace, proposal, decision, tool_result, final, events, alerts=(), session_state="NORMAL") -> dict:
        return _jsonable({
            "run_id": run_id, "company": "Northstar Freight (synthetic)", "model": MODEL_PROFILE,
            "user": asdict(user), "prompt": prompt, "scope": scope, "trace": trace,
            "proposal": proposal, "decision": decision, "tool_result": tool_result, "final_status": final,
            "events": events, "alerts": alerts, "session_state": session_state,
            "safety_note": "All tool results and customer updates are synthetic. No external system is contacted.",
        })
