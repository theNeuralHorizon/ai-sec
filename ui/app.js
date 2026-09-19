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
  if ([
    "DENY", "CONTAINED", "QUARANTINE_SESSION", "BLOCKED", "REFUSED",
    "SENSITIVE_EXFILTRATION", "PROMPT_INJECTION", "OUT_OF_SCOPE",
  ].includes(value)) return "crit";
  if ([
    "ALLOW", "NORMAL", "ALLOW_WITH_REDACTION", "COMPLETED",
    "IN_SCOPE", "BOUND", "SIMULATED_RESULT", "PROPOSED",
  ].includes(value)) return "ok";
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
    const missing = value === null || value === undefined;
    dd.textContent = missing ? "—" : String(value);
    dd.className = missing ? "faint" : (tone || "");
    wrap.append(dt, dd);
    node.append(wrap);
  }
}

function segmentNode(tag, location, text, why, kind) {
  const box = document.createElement("div");
  box.className = `seg ${kind || ""}`.trim();
  const meta = document.createElement("div");
  meta.className = "seg-meta";
  const t = document.createElement("span");
  t.className = "seg-tag";
  t.textContent = tag;
  meta.append(t);
  if (location) {
    const loc = document.createElement("span");
    loc.className = "seg-loc";
    loc.textContent = location;
    meta.append(loc);
  }
  const body = document.createElement("div");
  body.className = "seg-text";
  body.textContent = text;
  box.append(meta, body);
  if (why) {
    const note = document.createElement("div");
    note.className = "seg-why";
    note.textContent = why;
    box.append(note);
  }
  return box;
}

function renderTrace(host, noteNode, events, emptyText) {
  host.replaceChildren();
  if (!events.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = emptyText;
    host.append(li);
    noteNode.textContent = "0 events";
    return;
  }
  noteNode.textContent = `${events.length} events`;
  for (const event of events) {
    const li = document.createElement("li");
    li.className = toneOf(event.outcome);
    const top = document.createElement("div");
    top.className = "t-top";
    const kind = document.createElement("span");
    kind.className = "t-kind";
    kind.textContent = event.event_type || event.stage;
    const out = document.createElement("span");
    out.className = `t-out ${toneOf(event.outcome)}`;
    out.textContent = event.outcome;
    top.append(kind, out);
    const detail = document.createElement("div");
    detail.className = "t-rule";
    detail.textContent = event.detail || event.policy_rule_id ||
      (event.details && event.details.from ? `from ${event.details.from}` : "—");
    li.append(top, detail);
    host.append(li);
  }
}

/* ===================== attack scenarios ===================== */

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
    host.append(segmentNode("QUARANTINED", seg.location, seg.text, why, "quarantined"));
  }
  for (const seg of evidence) host.append(segmentNode("EVIDENCE", seg.location, seg.text, "", ""));
}

function renderScenario(data) {
  const copy = SCENARIO_COPY[data.scenario] || { label: "", line: "" };
  const actionDecision = data.action_decision?.decision ?? null;
  const rule = data.action_decision?.rule_id ?? null;
  const contextDecision = data.context.decision?.decision ?? null;
  const sessionState = data.session_state;

  $("verdict").className = `verdict ${data.protection_enabled ? toneOf(actionDecision) : "crit"}`;
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
  renderTrace($("trace"), $("trace-note"), data.events || [], "No telemetry — the control plane was not in the path.");
}

async function loadScenario(name) {
  document.querySelectorAll("[data-scenario]").forEach((b) => {
    b.classList.toggle("active", b.dataset.scenario === name);
  });
  const response = await fetch(`/api/scenarios/${name}`, { cache: "no-store" });
  if (!response.ok) throw new Error(`Scenario failed: ${response.status}`);
  renderScenario(await response.json());
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

/* ===================== live console ===================== */

let COMPANY = null;

function renderOrg(actingId) {
  const host = $("org-grid");
  host.replaceChildren();
  const users = Object.values(COMPANY.users);
  for (const user of users) {
    const card = document.createElement("div");
    card.className = `person ${user.user_id === actingId ? "is-acting" : ""}`.trim();

    const name = document.createElement("div");
    name.className = "p-name";
    name.textContent = user.name;

    const role = document.createElement("div");
    role.className = "p-role";
    role.textContent = user.role;

    const dept = document.createElement("div");
    dept.className = "p-dept";
    dept.textContent = user.department;

    const line = document.createElement("div");
    line.className = "p-line";
    const manager = user.reports_to ? COMPANY.users[user.reports_to] : null;
    line.textContent = manager ? `reports to ${manager.name}` : "team lead · can approve outbound";

    const clear = document.createElement("div");
    clear.className = "p-clear";
    for (const label of user.clearance) {
      const chip = document.createElement("span");
      chip.className = `lbl ${label}`;
      chip.textContent = label;
      clear.append(chip);
    }
    card.append(name, role, dept, line, clear);
    host.append(card);
  }
}

function renderMatrix() {
  const host = $("matrix");
  host.replaceChildren();
  const users = Object.values(COMPANY.users);
  const tools = Object.keys(COMPANY.tools);
  const labels = ["public", "internal", "confidential", "pii"];
  const cols = [...tools, ...labels, "approve"];
  host.style.gridTemplateColumns = `minmax(110px, 1.2fr) repeat(${cols.length}, minmax(64px, 1fr))`;

  const blank = document.createElement("div");
  blank.className = "mx-cell mx-head";
  host.append(blank);
  for (const col of cols) {
    const head = document.createElement("div");
    head.className = "mx-cell mx-head";
    head.textContent = col.replace("company.files.", "").replace("customer.", "").replace("shipment.", "");
    head.title = col;
    host.append(head);
  }

  for (const user of users) {
    const rowHead = document.createElement("div");
    rowHead.className = "mx-cell mx-row-head";
    rowHead.textContent = user.name;
    host.append(rowHead);

    for (const tool of tools) {
      const on = user.tools.includes(tool);
      const cell = document.createElement("div");
      cell.className = `mx-cell ${on ? "mx-on" : "mx-off"}`;
      cell.textContent = on ? "●" : "·";
      cell.title = `${user.name} ${on ? "may" : "may not"} use ${tool}`;
      host.append(cell);
    }
    for (const label of labels) {
      const on = user.clearance.includes(label);
      const cell = document.createElement("div");
      cell.className = `mx-cell ${on ? "mx-on" : "mx-off"}`;
      cell.textContent = on ? "●" : "·";
      cell.title = `${user.name} ${on ? "is cleared for" : "is not cleared for"} ${label}`;
      host.append(cell);
    }
    const approve = document.createElement("div");
    approve.className = `mx-cell ${user.can_approve_notifications ? "mx-approve" : "mx-off"}`;
    approve.textContent = user.can_approve_notifications ? "●" : "·";
    approve.title = `${user.name} ${user.can_approve_notifications ? "can" : "cannot"} approve outbound updates`;
    host.append(approve);
  }
}

async function loadCompany() {
  const response = await fetch("/api/company", { cache: "no-store" });
  COMPANY = await response.json();

  const select = $("user-id");
  select.replaceChildren();
  for (const user of Object.values(COMPANY.users)) {
    const option = document.createElement("option");
    option.value = user.user_id;
    option.textContent = `${user.name} — ${user.role}`;
    select.append(option);
  }
  select.value = "atharva.ops";
  select.addEventListener("change", () => renderOrg(select.value));

  $("model-chip").textContent = COMPANY.model.parameter_class + " · untrusted planner";
  $("model-chip").title = COMPANY.model.boundary;

  renderOrg(select.value);
  renderMatrix();
}

const FLOW_ORDER = ["identity", "scope", "model", "policy", "tool"];

function resetFlow() {
  for (const node of document.querySelectorAll(".node")) {
    node.className = "node";
    node.querySelector(".n-state").textContent = "—";
  }
}

/** Replay the run one stage at a time so the block point is visible, not just final. */
function animateFlow(result) {
  resetFlow();
  const byStage = new Map();
  for (const step of result.trace) byStage.set(step.stage, step);

  const stopped = ["REFUSED", "BLOCKED"].includes(result.final_status);
  const held = result.final_status === "AWAITING_APPROVAL";
  let delay = 0;

  for (const stage of FLOW_ORDER) {
    const node = document.querySelector(`.node[data-stage="${stage}"]`);
    const step = byStage.get(stage);
    setTimeout(() => {
      if (!step) {
        node.className = "node";
        node.querySelector(".n-state").textContent = stopped ? "not reached" : "—";
        return;
      }
      const tone = toneOf(step.outcome);
      const isStop = tone === "crit";
      const isHeld = tone === "warn" || step.outcome === "HELD";
      node.className = `node active ${isStop ? "stopped" : isHeld ? "held" : "done"}`;
      node.querySelector(".n-state").textContent = step.outcome;
    }, delay);
    delay += 180;
  }

  setTimeout(() => {
    const verdict = $("live-verdict");
    verdict.className = `verdict ${stopped ? "crit" : held ? "warn" : "ok"}`;
    $("live-status").textContent = {
      COMPLETED: "Allowed — the request was inside this person's authority",
      AWAITING_APPROVAL: "Held for human approval",
      BLOCKED: "Blocked by policy",
      REFUSED: "Refused before the model was given a tool",
    }[result.final_status] || result.final_status;
    $("live-reason").textContent = result.decision.reason;
    $("live-rule").textContent = `${result.decision.rule_id} · policy ${result.decision.policy_version} · run ${result.run_id}`;
  }, delay);
}

function renderRunResult(result) {
  const host = $("tool-result");
  host.replaceChildren();

  const proposal = result.proposal;
  $("result-note").textContent = proposal ? proposal.tool_name : "no tool proposed";

  const scope = result.scope.assessment;
  host.append(segmentNode(
    `SCOPE · ${scope.verdict}`, `confidence ${Math.round(scope.confidence * 100)}%`,
    scope.reason, (scope.signals || []).join("  ") || "",
    toneOf(scope.verdict) === "ok" ? "good" : "quarantined",
  ));

  if (result.model_observation) {
    host.append(segmentNode("MODEL PROPOSAL", result.model_observation.mode,
      result.model_observation.plan, "the model only proposes; it authorises nothing", ""));
  }

  if (result.tool_result) {
    host.append(segmentNode("TOOL RESULT", result.tool_result.tool, result.tool_result.summary, "", "good"));
    for (const document_ of result.tool_result.documents || []) {
      host.append(segmentNode(`DOC · ${document_.label}`, document_.path, document_.summary, "", ""));
    }
  } else {
    host.append(segmentNode("TOOL RESULT", "", "No tool was executed — nothing left this machine.", "", ""));
  }
}

async function runTask(userId, prompt, approvalGranted) {
  const button = $("run-btn");
  button.disabled = true;
  button.textContent = "Running…";
  resetFlow();
  try {
    const response = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: userId, prompt, approval_granted: approvalGranted }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Run failed: ${response.status}`);
    renderOrg(userId);
    animateFlow(result);
    renderRunResult(result);
    renderTrace($("live-trace"), $("live-trace-note"), result.trace, "No trace.");
  } catch (error) {
    $("live-verdict").className = "verdict crit";
    $("live-status").textContent = "Could not run";
    $("live-reason").textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = "Run through Aegis";
  }
}

$("run-form").addEventListener("submit", (event) => {
  event.preventDefault();
  runTask($("user-id").value, $("prompt").value.trim(), $("approval").checked);
});

for (const example of document.querySelectorAll(".examples button")) {
  example.addEventListener("click", () => {
    $("user-id").value = example.dataset.user;
    $("prompt").value = example.dataset.prompt;
    runTask(example.dataset.user, example.dataset.prompt, $("approval").checked);
  });
}

async function loadBenchmarks() {
  const response = await fetch("/api/benchmarks", { cache: "no-store" });
  const report = await response.json();
  const host = $("bench");
  host.replaceChildren();
  $("bench-note").textContent = `${report.cases.length} synthetic cases`;

  const labels = {
    prompt_to_plan_alignment: "Prompt to plan alignment",
    expected_outcome_alignment: "Expected outcome alignment",
    workflow_drift_rate: "Workflow drift",
    unsafe_request_refusal_rate: "Unsafe request refusal",
  };

  for (const [key, label] of Object.entries(labels)) {
    const value = report.metrics[key];
    const row = document.createElement("div");
    row.className = "bm";
    const name = document.createElement("span");
    name.className = "bm-name";
    name.textContent = label;
    const val = document.createElement("span");
    val.className = "bm-val";
    val.textContent = `${Math.round(value * 100)}%`;
    const track = document.createElement("div");
    track.className = "bm-track";
    const fill = document.createElement("div");
    // Drift is the one metric where a high bar is bad.
    fill.className = `bm-fill ${key === "workflow_drift_rate" && value > 0 ? "crit" : ""}`.trim();
    track.append(fill);
    row.append(name, val, track);
    host.append(row);
    requestAnimationFrame(() => { fill.style.width = `${value * 100}%`; });
  }

  for (const testCase of report.cases) {
    const line = document.createElement("div");
    line.className = "bm-case";
    const tick = document.createElement("span");
    tick.className = `bm-tick ${testCase.drift ? "crit" : "ok"}`;
    tick.textContent = testCase.drift ? "✕" : "✓";
    const name = document.createElement("span");
    name.textContent = testCase.name;
    const rule = document.createElement("span");
    rule.className = "mono";
    rule.textContent = `${testCase.actual_status} · ${testCase.rule_id}`;
    line.append(tick, name, rule);
    host.append(line);
  }
}

/* ===================== chrome ===================== */

for (const tab of document.querySelectorAll("[data-tab]")) {
  tab.addEventListener("click", () => {
    document.querySelectorAll("[data-tab]").forEach((t) => t.classList.toggle("active", t === tab));
    $("tab-console").hidden = tab.dataset.tab !== "console";
    $("tab-scenarios").hidden = tab.dataset.tab !== "scenarios";
  });
}

function applyTheme(theme) {
  if (theme) document.documentElement.setAttribute("data-theme", theme);
  else document.documentElement.removeAttribute("data-theme");
}
try { applyTheme(localStorage.getItem("aegis-theme")); } catch { /* system theme stands */ }

$("theme-toggle").addEventListener("click", () => {
  const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
  applyTheme(next);
  try { localStorage.setItem("aegis-theme", next); } catch { /* not persisted */ }
});

loadCompany().catch(() => { $("model-chip").textContent = "company data unavailable"; });
loadBenchmarks().catch(() => { $("bench-note").textContent = "benchmarks unavailable"; });
loadScenario("bypass").catch(() => {});
