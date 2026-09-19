# Aegis MVP Build Handoff

## Current state

The repository now contains a working, local, dependency-free vertical slice of the Aegis Agent Security Control Plane.

Implemented capabilities:

- provenance-aware HTML inspection with visible, hidden, comment, and attribute content extraction;
- indirect prompt-injection signals, normalization, quarantining, and trust labels;
- deterministic context and tool policy with stable rule identifiers;
- task-scoped tool capabilities, data clearances, destinations, and approval checks;
- bidirectional Context DLP for ingress redaction and egress-sensitive-data detection;
- correlated Agent EDR events, alerts, session state, and containment;
- clean, detected-attack, deliberate detector-bypass, and unprotected-baseline demonstrations;
- a local judge-facing dashboard; and
- a transparent synthetic evaluation harness with documented limitations.

The prototype makes no real external tool calls or side effects. All email, data access, and destructive actions shown in the demonstrations are proposals evaluated by policy only.

## How to verify the current build

From PowerShell in the repository root:

```powershell
$env:PYTHONPATH='src'
python -m unittest discover -s tests -v
python -m aegis.demo all
python -m aegis.eval
```

To run the dashboard:

```powershell
$env:PYTHONPATH='src'
python -m aegis.webapp
```

Then open `http://127.0.0.1:8080`.

## Work remaining

### Next implementation milestone

1. Add a task-scoped runtime API for creating runs, analyzing supplied content, requesting action decisions, and reading EDR events.
2. Keep that API fail-closed, validate and size-limit all inputs, redact sensitive telemetry, and ensure it authorizes actions without executing them.
3. Connect the dashboard to live runtime runs in addition to the fixed demonstration scenarios.

### Agent and tool integration

1. Add a Google ADK integration as a clearly separated adapter, not as a core policy dependency.
2. Add an MCP enforcement adapter that intercepts tool requests before execution.
3. Define signed or otherwise integrity-protected task mandates and bind them to authenticated agent identities.
4. Add optional adapters for URL reputation and threat-intelligence providers while keeping the local demo deterministic.

### Security hardening

1. Replace in-memory run state with an append-only, access-controlled telemetry store.
2. Add authentication, authorization, rate limiting, request-size limits, and secure deployment defaults around the runtime service.
3. Expand normalization and file handling beyond HTML, including PDF and office-document extraction in isolated workers.
4. Strengthen DLP detection, structured-data handling, destination classification, and log redaction.
5. Add policy versioning, configuration validation, policy tests, and an administrative review workflow.
6. Threat-model the service and adapters, then add abuse-case, fuzz, and concurrency testing.

### Evaluation and evidence

1. Expand the small synthetic fixture set into versioned benign and adversarial corpora.
2. Measure detection, policy-block, false-positive, latency, and containment outcomes separately.
3. Add reproducible benchmark metadata and avoid presenting synthetic results as production performance.
4. Map evidence to relevant ISO/IEC 27001:2022 and ISO/IEC 42001:2023 control objectives without claiming certification or guaranteed compliance.

### Product and demo polish

1. Add a concise pitch script and panel Q&A grounded in what the prototype actually proves.
2. Improve accessibility and responsive behavior in the dashboard.
3. Add exportable incident timelines and policy-decision evidence for the final presentation.
4. Package a repeatable local demo and, only after security review, a deployable environment.

## Important boundaries

- Aegis is SafeContext-inspired; it is not a reconstruction of undisclosed SafeContext internals and is not affiliated with Palo Alto Networks.
- Current evaluation results come from a deliberately small synthetic corpus and are not production benchmarks.
- The current build demonstrates enforcement and containment architecture, not comprehensive prompt-injection detection.
- Real tool execution must remain outside the security decision service and must require an explicit allow decision tied to the same run and request.
