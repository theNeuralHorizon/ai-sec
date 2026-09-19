const statusNode = document.querySelector("#status");
const contextNode = document.querySelector("#context");
const policyNode = document.querySelector("#policy");
const edrNode = document.querySelector("#edr");
const timelineNode = document.querySelector("#timeline");

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function row(label, value, tone = "") {
  const rendered = value === null || value === undefined ? "—" : value;
  return `<div><dt>${escapeHtml(label)}</dt><dd class="${escapeHtml(tone)}">${escapeHtml(rendered)}</dd></div>`;
}

function decisionTone(value) {
  if (["DENY", "CONTAINED", "ALLOW_READ_ONLY"].includes(value)) return "bad";
  if (value === "ALLOW") return "good";
  return "warn";
}

function render(data) {
  const contextDecision = data.context.decision?.decision ?? "NOT INSPECTED";
  const actionDecision = data.action_decision?.decision ?? "NOT ENFORCED";
  const rule = data.action_decision?.rule_id ?? "PROTECTION DISABLED";
  const findingCount = data.context.findings?.length ?? 0;

  statusNode.className = `status ${decisionTone(actionDecision)}`;
  statusNode.textContent = data.side_effect_would_execute
    ? "Unsafe action would execute — shown safely through a no-op stub."
    : actionDecision === "DENY"
      ? "Unsafe side effect prevented."
      : "Task continued within policy.";

  contextNode.innerHTML =
    row("Admission", contextDecision, decisionTone(contextDecision)) +
    row("Risk score", data.context.risk_score) +
    row("Findings", findingCount) +
    row("Quarantined", data.context.quarantined_count);

  policyNode.innerHTML =
    row("Tool", data.proposed_action.tool_name) +
    row("Destination", data.proposed_action.destination) +
    row("Decision", actionDecision, decisionTone(actionDecision)) +
    row("Rule", rule);

  edrNode.innerHTML =
    row("Session", data.session_state, decisionTone(data.session_state)) +
    row("Alerts", data.alerts.length) +
    row("Response", data.alerts.at(-1)?.response ?? "observe");

  const events = data.events.map((event) =>
    `<li><span>${escapeHtml(event.event_type)}</span><strong>${escapeHtml(event.outcome)}</strong><code>${escapeHtml(event.policy_rule_id ?? event.details?.from ?? "—")}</code></li>`
  );
  if (data.side_effect_would_execute) {
    events.push("<li><span>tool.stub</span><strong>WOULD EXECUTE</strong><code>NO REAL SIDE EFFECT</code></li>");
  }
  timelineNode.innerHTML = events.join("") || "<li>No security telemetry because protection is disabled.</li>";
}

async function loadScenario(name) {
  statusNode.textContent = "Running scenario…";
  document.querySelectorAll("button").forEach((button) => {
    button.classList.toggle("active", button.dataset.scenario === name);
  });
  const response = await fetch(`/api/scenarios/${name}`, { cache: "no-store" });
  if (!response.ok) throw new Error(`Scenario failed: ${response.status}`);
  render(await response.json());
}

document.querySelectorAll("button[data-scenario]").forEach((button) => {
  button.addEventListener("click", () => loadScenario(button.dataset.scenario).catch((error) => {
    statusNode.textContent = error.message;
    statusNode.className = "status bad";
  }));
});

loadScenario("clean").catch(() => {});
