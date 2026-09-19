# Aegis

Aegis is an agent security control plane that treats external content as untrusted input, protects AI agents from indirect prompt injection, and blocks unsafe tool actions.

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
