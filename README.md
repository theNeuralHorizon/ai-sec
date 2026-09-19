# Aegis

> Inspect what enters. Control what executes. Contain what gets compromised.

Aegis is a local agent-security control plane. This branch provides a complete synthetic supply-chain demo for **Northstar Freight**: a deliberately permissive 3.8B (4B-class) abliterated-model route is treated as untrusted, while Aegis independently limits scope, tools, role permissions, data movement, and session behavior.

## What the demo proves

- Four role-scoped users: Operations Manager, Procurement Analyst, Finance Controller, and Customer Support Associate.
- Nine normal, labeled supply-chain documents in [`fixtures/company`](fixtures/company).
- Three local, side-effect-free tools: document search, shipment lookup, and a portal-only customer update.
- A multi-layer scope guard that refuses destructive, exfiltration, prompt-injection, and out-of-domain requests before model planning.
- Deterministic RBAC, data classification, destination, and approval rules with stable policy IDs.
- An EDR trace showing identity binding, scope decision, model proposal, tool-policy decision, and synthetic result.
- A transparent six-case alignment benchmark measuring prompt-to-plan alignment, expected outcome alignment, workflow drift, and unsafe-request refusal.

The configured model profile is [`marx161-cmd/phi35-mini-disinhibited-abliterated-3.8B`](https://huggingface.co/marx161-cmd/phi35-mini-disinhibited-abliterated-3.8B), which is 3.8B parameters—close to the requested 4B class. The checked-in demo uses a deterministic local planner because no local model runtime is installed in this workspace; it clearly labels that mode in the dashboard. To use an installed OpenAI-compatible local endpoint such as LM Studio or llama.cpp, set `AEGIS_LOCAL_MODEL_ENDPOINT` to its loopback `/v1/chat/completions` address and optionally `AEGIS_LOCAL_MODEL_NAME`. The model is asked for a short plan only—Aegis chooses/authorizes capabilities and every tool remains synthetic.

## Run it

PowerShell, from the repository root:

```powershell
$env:PYTHONPATH='src'
python -m unittest discover -s tests -v
python -m aegis.supply_eval
python -m aegis.webapp
```

Open [http://127.0.0.1:8080](http://127.0.0.1:8080). The dashboard lets you choose a user, run its sample prompts, add your own prompt, inspect every security layer, and view the benchmark results.

## Demo sequence

1. Run “Document search” as Eli; Aegis returns only his role-authorized contract summary.
2. Run “Approval gate” as Sam; the customer update is held until an authorized approval exists.
3. Run “Egress refusal”; sensitive-manifest emailing is refused before any model tool plan.
4. Run “Injection refusal”; instruction override is refused before the model receives a tool-capable task.
5. Review the benchmark strip to show that expected user intent, model plan, and policy outcome remain aligned on the supplied corpus.

All users, records, contacts, files, tools, and results are synthetic. No real email, customer portal update, carrier query, or destructive action is executed.

## Existing technical demonstration

The original context-gateway demonstrations remain available:

```powershell
$env:PYTHONPATH='src'
python -m aegis.demo all
python -m aegis.eval
```

## Documents

- [Northstar Freight Policy Rubric](POLICY_RUBRIC.md)
- [Aegis Hackathon Prototype Design](AEGIS_HACKATHON_PROTOTYPE_DESIGN.md)
- [Aegis Agent Security Control Plane](AEGIS_EDR_IDEA.md)
