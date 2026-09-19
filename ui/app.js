const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? "—").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
const tone = (value) => value === "COMPLETED" || value === "ALLOW" ? "good" : value === "AWAITING_APPROVAL" ? "warn" : "bad";
function renderCompany(data) {
  $("#model-card").innerHTML = `<b>${escapeHtml(data.model.parameter_class)}</b><span>${escapeHtml(data.model.model_id)}</span><small>${escapeHtml(data.model.mode)}</small>`;
  $("#user-id").innerHTML = Object.values(data.users).map((user) => `<option value="${escapeHtml(user.user_id)}">${escapeHtml(user.name)} — ${escapeHtml(user.role)}</option>`).join("");
  $("#people").innerHTML = Object.values(data.users).map((user) => `<div class="person"><b>${escapeHtml(user.name)}</b><span>${escapeHtml(user.role)}</span><small>${escapeHtml(user.clearance.join(" · "))}</small></div>`).join("");
  $("#tools").innerHTML = Object.values(data.tools).map((tool) => `<p><b>${escapeHtml(tool.name)}</b><span>${escapeHtml(tool.action_class)} · ${escapeHtml(tool.label)}</span></p>`).join("");
  $("#files").innerHTML = data.files.map((file) => `<p><b>${escapeHtml(file.title)}</b><span>${escapeHtml(file.label)} · ${escapeHtml(file.path)}</span></p>`).join("");
}
function list(items, render) { return items?.length ? items.map(render).join("") : "<li>No events recorded.</li>"; }
function renderRun(data) {
  $("#run-state").textContent = `Run ${data.run_id}`; $("#final-status").textContent = data.final_status; $("#final-status").className = tone(data.final_status); $("#decision-reason").textContent = data.decision.reason; $("#rule-id").textContent = data.decision.rule_id;
  $("#proposal").innerHTML = data.proposal ? `<b>${escapeHtml(data.proposal.tool_name)}</b><small>${escapeHtml(data.model_observation?.mode || "policy-bound model")}</small><pre>${escapeHtml(data.model_observation?.plan || "")}</pre><pre>${escapeHtml(JSON.stringify(data.proposal.arguments, null, 2))}</pre>` : "Model proposal withheld before tool planning.";
  $("#tool-result").innerHTML = data.tool_result ? `<b>${escapeHtml(data.tool_result.summary)}</b><pre>${escapeHtml(JSON.stringify(data.tool_result.data || data.tool_result.documents || {}, null, 2))}</pre>` : data.final_status === "AWAITING_APPROVAL" ? "Held before any outbound simulation." : "No tool result.";
  $("#layers").innerHTML = list(data.scope.layers, (layer) => `<li><b>${escapeHtml(layer.name)}</b><span class="${tone(layer.result)}">${escapeHtml(layer.result)}</span><small>${escapeHtml(layer.detail)}</small></li>`);
  $("#trace").innerHTML = list(data.trace, (event) => `<li><b>${escapeHtml(event.stage)}</b><span class="${tone(event.outcome)}">${escapeHtml(event.outcome)}</span><small>${escapeHtml(event.detail)}</small></li>`);
  $("#events").innerHTML = list(data.events, (event) => `<li><b>${escapeHtml(event.event_type)}</b><span class="${tone(event.outcome)}">${escapeHtml(event.outcome)}</span><small>${escapeHtml(event.policy_rule_id || "no rule")}</small></li>`);
}
function renderBenchmarks(data) { $("#metrics").innerHTML = Object.entries(data.metrics).map(([name, value]) => `<div><b>${escapeHtml((value * 100).toFixed(0))}%</b><span>${escapeHtml(name.replaceAll("_", " "))}</span></div>`).join(""); $("#benchmark-cases").innerHTML = data.cases.map((item) => `<div><b>${escapeHtml(item.name)}</b><span class="${item.drift ? "bad" : "good"}">${item.drift ? "DRIFT" : "ALIGNED"}</span><small>${escapeHtml(item.actual_status)} · ${escapeHtml(item.rule_id)}</small></div>`).join(""); }
async function request(url, options) { const response = await fetch(url, options); const data = await response.json(); if (!response.ok) throw new Error(data.error || `Request failed: ${response.status}`); return data; }
$("#run-form").addEventListener("submit", async (event) => { event.preventDefault(); $("#run-state").textContent = "Running scope and policy checks…"; try { renderRun(await request("/api/run", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({user_id: $("#user-id").value, prompt: $("#prompt").value, approval_granted: $("#approval").checked})})); } catch (error) { $("#run-state").textContent = error.message; } });
document.querySelectorAll(".examples button").forEach((button) => button.addEventListener("click", () => { $("#user-id").value = button.dataset.user; $("#prompt").value = button.dataset.prompt; $("#approval").checked = false; $("#run-form").requestSubmit(); }));
Promise.all([request("/api/company"), request("/api/benchmarks")]).then(([company, benchmarks]) => { renderCompany(company); renderBenchmarks(benchmarks); }).catch((error) => { $("#run-state").textContent = error.message; });
