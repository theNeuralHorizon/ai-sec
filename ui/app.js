const $ = (id) => document.getElementById(id);

const SCENARIO_COPY = {
  baseline: {
    label: "The agent would have sent it",
    line: "No gateway, no policy, no session monitoring. A hidden instruction on a product page redirects the task and nothing stands between it and the tool call. Shown as a no-op stub — nothing is actually sent.",
  },
  caught: {
    label: "Blocked because of where the instruction came from",
    line: "The gateway found the concealed payload and quarantined it. The agent was permitted to use email.send, and the message body is harmless — the block comes from provenance, not from the content being sent.",
  },
  bypass: {
    label: "Nothing was detected. The action was still stopped.",
    line: "This page evades the detector entirely: zero findings, risk score zero, context admitted. The payload is classified at egress instead, and the agent has no clearance to move it. This is the case a classifier alone does not cover.",
  },
  clean: {
    label: "Benign page, task completes",
    line: "No findings, no quarantine, no containment. The control plane stays out of the way when nothing is wrong — the same rules that blocked the attacks allow this through.",
  },
};

const DENY_RULES = {
  "POL-FLOW-001": "Suspicious external content cannot influence a side-effecting action.",
  "POL-DATA-001": "The agent lacks clearance for one or more data labels.",
  "POL-DLP-001": "Sensitive data cannot flow to an unapproved external destination.",
  "POL-CAP-001": "The requested tool is explicitly forbidden by the task mandate.",
  "POL-CAP-002": "The requested tool is outside the task-scoped capability set.",
};

function toneOf(value) {
  if (["DENY", "CONTAINED", "QUARANTINE_SESSION"].includes(value)) return "crit";
  if (["ALLOW", "NORMAL", "ALLOW_WITH_REDACTION"].includes(value)) return "ok";
  if (value === null || value === undefined) return "";
  return "warn";
}

function rows(node, items) {
  node.replaceChildren();
  for (const [label, value, tone] of items) {
    const wrap = document.createElement("div");
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value === null || value === undefined ? "—" : String(value);
    dd.className = value === null || value === undefined ? "faint" : (tone || "");
    wrap.append(dt, dd);
    node.append(wrap);
  }
}

function renderSegments(data) {
  const host = $("segments");
  host.replaceChildren();
  const quarantined = data.context.quarantined || [];
  const evidence = data.context.evidence || [];
  const findings = data.context.findings || [];

  if (!data.protection_enabled) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = "Protection is off, so nothing inspected this page. The agent saw the hidden instruction as ordinary text.";
    host.append(p);
    $("evidence-note").textContent = "not inspected";
    return;
  }

  $("evidence-note").textContent = `${evidence.length} kept · ${quarantined.length} quarantined`;

  for (const seg of quarantined) {
    const why = findings
      .filter((f) => f.location === seg.location)
      .map((f) => `${f.rule_id} · ${f.category} · ${Math.round(f.confidence * 100)}%`)
      .join("   ");
    host.append(segmentNode(seg, true, why));
  }
  for (const seg of evidence) host.append(segmentNode(seg, false, ""));

  if (!quarantined.length && !evidence.length) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = "No content segments returned.";
    host.append(p);
  }
}

function segmentNode(seg, isQuarantined, why) {
  const box = document.createElement("div");
  box.className = isQuarantined ? "seg quarantined" : "seg";

  const meta = document.createElement("div");
  meta.className = "seg-meta";
  const tag = document.createElement("span");
  tag.className = "seg-tag";
  tag.textContent = isQuarantined ? "QUARANTINED" : "EVIDENCE";
  const loc = document.createElement("span");
  loc.className = "seg-loc";
  loc.textContent = seg.location;
  meta.append(tag, loc);

  const text = document.createElement("div");
  text.className = "seg-text";
  text.textContent = seg.text;

  box.append(meta, text);

  if (why) {
    const note = document.createElement("div");
    note.className = "seg-why";
    note.textContent = why;
    box.append(note);
  }
  return box;
}

function renderTrace(data) {
  const host = $("trace");
  host.replaceChildren();
  const events = data.events || [];

  if (!events.length) {
    const p = document.createElement("li");
    p.className = "empty";
    p.textContent = "No telemetry — the control plane was not in the path.";
    host.append(p);
    $("trace-note").textContent = "0 events";
    return;
  }

  $("trace-note").textContent = `${events.length} events`;
  for (const event of events) {
    const li = document.createElement("li");
    li.className = toneOf(event.outcome);

    const top = document.createElement("div");
    top.className = "t-top";
    const kind = document.createElement("span");
    kind.className = "t-kind";
    kind.textContent = event.event_type;
    const out = document.createElement("span");
    out.className = `t-out ${toneOf(event.outcome)}`;
    out.textContent = event.outcome;
    top.append(kind, out);

    const rule = document.createElement("div");
    rule.className = "t-rule";
    rule.textContent = event.policy_rule_id || (event.details && event.details.from ? `from ${event.details.from}` : "—");

    li.append(top, rule);
    host.append(li);
  }
}

function render(data) {
  const copy = SCENARIO_COPY[data.scenario] || { label: "", line: "" };
  const actionDecision = data.action_decision?.decision ?? null;
  const rule = data.action_decision?.rule_id ?? null;
  const contextDecision = data.context.decision?.decision ?? null;
  const sessionState = data.session_state;

  const verdict = $("verdict");
  verdict.className = `verdict ${data.protection_enabled ? toneOf(actionDecision) : "crit"}`;
  $("verdict-label").textContent = copy.label;
  $("verdict-line").textContent = copy.line;

  const mandate = data.mandate || {};
  $("m-purpose").textContent = mandate.purpose ?? "—";
  $("m-source").textContent = data.source_url ?? "—";
  $("m-allowed").textContent = (mandate.allowed_tools || []).join(", ") || "—";
  $("m-clearance").textContent = (mandate.data_clearance || []).join(", ") || "—";

  const findings = data.context.findings || [];
  $("context-chip").textContent = data.protection_enabled ? (contextDecision ?? "—") : "NOT INSPECTED";
  $("context-chip").className = `chip ${data.protection_enabled ? toneOf(contextDecision) : "crit"}`;
  rows($("context-rows"), [
    ["Risk score", data.context.risk_score, findings.length ? "warn" : "ok"],
    ["Findings", data.protection_enabled ? findings.length : null],
    ["Quarantined", data.protection_enabled ? data.context.quarantined_count : null],
    ["Source trust", data.context.source_trust, findings.length ? "warn" : ""],
  ]);

  $("policy-chip").textContent = data.protection_enabled ? (actionDecision ?? "—") : "NOT ENFORCED";
  $("policy-chip").className = `chip ${data.protection_enabled ? toneOf(actionDecision) : "crit"}`;
  rows($("policy-rows"), [
    ["Tool", data.proposed_action.tool_name],
    ["Destination", data.proposed_action.destination],
    ["Rule", rule, toneOf(actionDecision)],
    ["Because", rule ? DENY_RULES[rule] ?? data.action_decision?.reason : null],
  ]);

  const alerts = data.alerts || [];
  $("edr-chip").textContent = sessionState ?? "—";
  $("edr-chip").className = `chip ${data.protection_enabled ? toneOf(sessionState) : "crit"}`;
  rows($("edr-rows"), [
    ["Session", sessionState, toneOf(sessionState)],
    ["Alerts", alerts.length],
    ["Last rule", alerts.at(-1)?.rule_id ?? null],
    ["Response", alerts.at(-1)?.response ?? (data.protection_enabled ? "observe" : null)],
  ]);

  $("stage-context").className = `stage ${findings.length ? "is-warm" : ""}`;
  $("stage-policy").className = `stage ${actionDecision === "DENY" ? "is-hot" : ""}`;
  $("stage-edr").className = `stage ${sessionState === "CONTAINED" ? "is-hot" : ""}`;

  renderSegments(data);
  renderTrace(data);
}

async function loadScenario(name) {
  document.querySelectorAll("[data-scenario]").forEach((b) => {
    b.classList.toggle("active", b.dataset.scenario === name);
  });
  const response = await fetch(`/api/scenarios/${name}`, { cache: "no-store" });
  if (!response.ok) throw new Error(`Scenario failed: ${response.status}`);
  render(await response.json());
}

document.querySelectorAll("[data-scenario]").forEach((button) => {
  button.addEventListener("click", () => {
    loadScenario(button.dataset.scenario).catch((error) => {
      $("verdict-label").textContent = "Could not load scenario";
      $("verdict-line").textContent = error.message;
      $("verdict").className = "verdict crit";
    });
  });
});

const toggle = $("theme-toggle");
function applyTheme(theme) {
  if (theme) document.documentElement.setAttribute("data-theme", theme);
  else document.documentElement.removeAttribute("data-theme");
}
try {
  applyTheme(localStorage.getItem("aegis-theme"));
} catch { /* storage unavailable; system theme stands */ }

toggle.addEventListener("click", () => {
  const isLight = document.documentElement.getAttribute("data-theme") === "light";
  const next = isLight ? "dark" : "light";
  applyTheme(next);
  try { localStorage.setItem("aegis-theme", next); } catch { /* not persisted */ }
});

loadScenario("bypass").catch(() => {});
