# Aegis

Aegis is an agent security control plane that treats external content as untrusted input, protects AI agents from indirect prompt injection, and blocks unsafe tool actions.

> Inspect what enters. Control what executes. Contain what gets compromised.

## Working prototype

The current vertical slice is fully local and dependency-free. It includes:

- a provenance-aware HTML Context Gateway;
- deterministic context and tool policy with stable rule IDs;
- task-scoped capabilities and data labels;
- Agent EDR session correlation and containment;
- clean, detected-attack, and deliberate detector-bypass scenarios; and
- a judge-facing local dashboard with no real external side effects.

Run the tests from PowerShell:

```powershell
$env:PYTHONPATH='src'
python -m unittest discover -s tests -v
```

Run the terminal demonstration:

```powershell
$env:PYTHONPATH='src'
python -m aegis.demo all
```

Run the dashboard:

```powershell
$env:PYTHONPATH='src'
python -m aegis.webapp
```

Then open `http://127.0.0.1:8080`.

All email, data-access, and destructive actions in the prototype are synthetic proposals. The demo never contacts an external system.

## Documents

- [Aegis Hackathon Prototype Design](AEGIS_HACKATHON_PROTOTYPE_DESIGN.md)
- [Aegis Agent Security Control Plane](AEGIS_EDR_IDEA.md)

## Core idea

```text
untrusted content
  -> inspect and label
  -> separate evidence from instructions
  -> enforce deterministic policy
  -> monitor the agent session
  -> contain unsafe actions
```
