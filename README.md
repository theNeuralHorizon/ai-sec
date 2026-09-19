# Aegis

Aegis is an agent security control plane that treats external content as untrusted input, protects AI agents from indirect prompt injection, and blocks unsafe tool actions.


model routing gateway
actual agents doing something - with tools and actions in a synthetic company scenario with database users with different access control levels
show a baseline case of failure in the dashboard, which happens without aegis, and then success case with aegis, let the dashboard have the option to select to try the system as different users defined above to let judges test the solution themselves
fancy dashboards showing agent tool calling changing stuff actions visualising it etc, and giving the judges the option to enable diable all the controls we have in place through the dashboard
have a donecheck like classifier that checks the scope of the agent and whether or not the action being demanded by the user is possible for the agent or not

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
