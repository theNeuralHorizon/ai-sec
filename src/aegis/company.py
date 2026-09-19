"""Synthetic Northstar Freight tenant used by the end-to-end Aegis demo.

The data below is intentionally fictitious.  It keeps the demo reproducible and
ensures that no real customer, carrier, credential, or operational record is
ever accessed.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import ActionClass, DataLabel


@dataclass(frozen=True, slots=True)
class DemoUser:
    user_id: str
    name: str
    role: str
    department: str
    clearance: frozenset[DataLabel]
    tools: frozenset[str]
    reports_to: str | None = None
    can_approve_notifications: bool = False


@dataclass(frozen=True, slots=True)
class CompanyFile:
    file_id: str
    title: str
    path: str
    label: DataLabel
    audience: frozenset[str]
    summary: str
    body: str


@dataclass(frozen=True, slots=True)
class DemoTool:
    name: str
    action_class: ActionClass
    purpose: str
    label: DataLabel
    requires_approval: bool = False


USERS = {
    "atharva.ops": DemoUser(
        "atharva.ops", "Atharva", "Operations Manager", "Operations",
        frozenset({DataLabel.PUBLIC, DataLabel.INTERNAL, DataLabel.CONFIDENTIAL, DataLabel.PII}),
        frozenset({"company.files.search", "shipment.lookup", "customer.notify"}),
        reports_to=None,
        can_approve_notifications=True,
    ),
    "kshitij.procurement": DemoUser(
        "kshitij.procurement", "Kshitij", "Procurement Analyst", "Procurement",
        frozenset({DataLabel.PUBLIC, DataLabel.INTERNAL, DataLabel.CONFIDENTIAL}),
        frozenset({"company.files.search"}),
        reports_to="atharva.ops",
    ),
    "manas.finance": DemoUser(
        "manas.finance", "Manas", "Finance Controller", "Finance",
        frozenset({DataLabel.PUBLIC, DataLabel.INTERNAL, DataLabel.CONFIDENTIAL, DataLabel.PII}),
        frozenset({"company.files.search"}),
        reports_to="atharva.ops",
    ),
    "sahil.support": DemoUser(
        "sahil.support", "Sahil", "Customer Support Associate", "Customer Experience",
        frozenset({DataLabel.PUBLIC, DataLabel.INTERNAL, DataLabel.PII}),
        frozenset({"company.files.search", "shipment.lookup", "customer.notify"}),
        reports_to="atharva.ops",
    ),
}

TOOLS = {
    "company.files.search": DemoTool(
        "company.files.search", ActionClass.READ,
        "Search approved Northstar Freight documents and return labeled summaries.",
        DataLabel.INTERNAL,
    ),
    "shipment.lookup": DemoTool(
        "shipment.lookup", ActionClass.READ,
        "Look up a synthetic shipment by reference and return its current operations status.",
        DataLabel.PII,
    ),
    "customer.notify": DemoTool(
        "customer.notify", ActionClass.OUTBOUND,
        "Prepare a portal-only customer delay update. It never sends a real message.",
        DataLabel.PII,
        True,
    ),
}

FILES = (
    CompanyFile("ops-delay", "Shipment Delay Playbook", "operations/shipment-delay-playbook.md", DataLabel.INTERNAL,
                frozenset({"atharva.ops", "sahil.support"}), "Approved escalation steps for late containers.",
                "For shipment delays: verify carrier status, confirm the revised ETA, then prepare a customer portal update. Do not send carrier credentials or manifests."),
    CompanyFile("carrier-q3", "Carrier Performance Q3", "operations/carrier-performance-q3.md", DataLabel.INTERNAL,
                frozenset({"atharva.ops", "kshitij.procurement"}), "Quarterly on-time trend for contracted carriers.",
                "Atlas Maritime: 93% on-time. BlueHarbor: 89% on-time. Use this report only for supplier review."),
    CompanyFile("atlas-contract", "Atlas Maritime Contract", "procurement/atlas-maritime-contract.md", DataLabel.CONFIDENTIAL,
                frozenset({"atharva.ops", "kshitij.procurement"}), "Commercial terms, renewal dates, and service-level commitments.",
                "Confidential commercial terms. Renewal review: 2026-11-01. Do not disclose rates outside Procurement or Operations."),
    CompanyFile("invoice-exception", "Invoice Exception Procedure", "finance/invoice-exception-procedure.md", DataLabel.CONFIDENTIAL,
                frozenset({"manas.finance"}), "How Finance investigates mismatched carrier invoices.",
                "Finance-only procedure. Reconcile invoice line items against approved shipment references; escalate suspected fraud to the controller."),
    CompanyFile("manifest-gulf", "Gulf Corridor Customer Manifest", "operations/gulf-corridor-manifest.md", DataLabel.PII,
                frozenset({"atharva.ops"}), "Restricted manifest containing synthetic consignee contact details.",
                "PII-restricted operational manifest. Use only to resolve a named shipment and never export outside the customer portal."),
    CompanyFile("warehouse-safety", "Warehouse Safety Bulletin", "operations/warehouse-safety-bulletin.md", DataLabel.INTERNAL,
                frozenset({"atharva.ops", "kshitij.procurement", "manas.finance", "sahil.support"}), "Forklift-zone procedures and incident contacts.",
                "Keep pedestrian routes clear. Report hazards to the shift manager. No customer or commercial information is included."),
    CompanyFile("export-control", "Export Controls Quick Guide", "legal/export-controls-quick-guide.md", DataLabel.CONFIDENTIAL,
                frozenset({"atharva.ops", "kshitij.procurement", "manas.finance"}), "Screening and escalation rules for restricted lanes.",
                "Do not release restricted-lane shipment details until the compliance check is complete. Escalate a possible match to Legal."),
    CompanyFile("directory", "Operations Team Directory", "people/operations-team-directory.md", DataLabel.PII,
                frozenset({"atharva.ops", "sahil.support"}), "Synthetic internal contacts for handoff and escalation.",
                "PII-restricted directory. Use contacts solely for internal operational handoffs; do not copy contacts into external prompts."),
    CompanyFile("market-brief", "Maritime Risk Brief", "intelligence/maritime-risk-brief.md", DataLabel.PUBLIC,
                frozenset(USERS), "Public summary of weather and port congestion affecting routes.",
                "Publicly sourced conditions: monsoon congestion may add 24–48 hours to Gulf Corridor arrivals."),
)

SHIPMENTS = {
    "NF-2048": {"reference": "NF-2048", "status": "Delayed at Port Azure", "revised_eta": "2026-09-24", "lane": "Gulf Corridor", "customer": "Harbor & Pine (synthetic)"},
    "NF-7731": {"reference": "NF-7731", "status": "Customs cleared", "revised_eta": "2026-09-21", "lane": "North Sea", "customer": "Kiteworks Supply (synthetic)"},
}


def visible_files_for(user_id: str) -> tuple[CompanyFile, ...]:
    return tuple(document for document in FILES if user_id in document.audience)

