# Aegis

> Inspect what enters. Control what executes. Contain what gets compromised.

Aegis is a local agent-security control plane. This branch provides a complete synthetic supply-chain demo for **Northstar Freight**: a 3.8B (4B-class) Q4 model route is treated as untrusted, while Aegis independently limits scope, tools, role permissions, data movement, and session behavior.

## What the demo proves

- Four role-scoped users: Operations Manager, Procurement Analyst, Finance Controller, and Customer Support Associate.
- Nine normal, labeled supply-chain documents in [`fixtures/company`](fixtures/company).
- Three local, side-effect-free tools: document search, shipment lookup, and a portal-only customer update.
- A multi-layer scope guard that refuses destructive, exfiltration, prompt-injection, and out-of-domain requests before model planning.
- Deterministic RBAC, data classification, destination, and approval rules with stable policy IDs.
- An EDR trace showing identity binding, scope decision, model proposal, tool-policy decision, and synthetic result.
- A transparent six-case alignment benchmark measuring prompt-to-plan alignment, expected outcome alignment, workflow drift, and unsafe-request refusal.

The exact abliterated checkpoint selected initially has no Q4 GGUF release, so the runnable profile is [`bartowski/Phi-3.5-mini-instruct-GGUF:Q4_K_M`](https://huggingface.co/bartowski/Phi-3.5-mini-instruct-GGUF), a 2.39 GB quantized Phi-3.5 Mini model. The model is asked for a short plan only—Aegis chooses/authorizes capabilities and every tool remains synthetic.

### Start the live Q4 model route

After the Q4 file is downloaded, use the prebuilt CUDA-enabled `llama-server.exe` from the `llama.cpp` release in one PowerShell terminal:

```powershell
Expand-Archive 'C:\Users\athar\AegisLocalModels\runtime\llama-b11050-bin-win-cuda-12.4-x64.zip' 'C:\Users\athar\AegisLocalModels\runtime\llama-cpp' -Force
& 'C:\Users\athar\AegisLocalModels\runtime\llama-cpp\llama-server.exe' -m 'C:\Users\athar\AegisLocalModels\phi35-mini-q4\Phi-3.5-mini-instruct-Q4_K_M.gguf' --host 127.0.0.1 --port 8081 -ngl 99 --ctx-size 2048
```

```powershell
$env:PYTHONPATH='src'
$env:AEGIS_LOCAL_MODEL_ENDPOINT='http://127.0.0.1:8081/v1/chat/completions'
$env:AEGIS_LOCAL_MODEL_NAME='bartowski/Phi-3.5-mini-instruct-GGUF:Q4_K_M'
python -m aegis.webapp
```

The UI remains available while the model downloads; it switches from deterministic fallback to `local model endpoint` in the “Model proposal” card when this route is running. The included `aegis.local_gguf_server` remains a CPU-only Python fallback for users who install `llama-cpp-python`.

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

### What the attack scenarios show

| Run | Gateway | Outcome | Rule |
| --- | --- | --- | --- |
| clean | no findings | task completes | `POL-ALLOW-000` |
| caught | hidden instruction quarantined | outbound action denied | `POL-FLOW-001` |
| bypass | nothing detected | outbound action denied anyway | `POL-DATA-001` |

The bypass run is the point: the detector misses the page, and the action is still stopped
at the policy boundary. Detection on the local corpus is 0.75 by design, because the
deliberate bypass counts as an undetected attack; action blocking is 1.0.

All email, data-access, and destructive actions in the prototype are synthetic proposals. The demo never contacts an external system.

## Documents

- [Northstar Freight Policy Rubric](POLICY_RUBRIC.md)
- [Aegis Hackathon Prototype Design](AEGIS_HACKATHON_PROTOTYPE_DESIGN.md)
- [Aegis Agent Security Control Plane](AEGIS_EDR_IDEA.md)
- [Backlog](BACKLOG.md)

## Core idea

```text
untrusted content
  -> inspect and label
  -> separate evidence from instructions
  -> enforce deterministic policy
  -> monitor the agent session
  -> contain unsafe actions
```
