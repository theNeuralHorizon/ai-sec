# Backlog

Scope ideas captured during the hackathon, moved here verbatim from the README so the
front page stays a usable quickstart. Nothing here is implemented yet.

- model routing gateway
- actual agents doing something - with tools and actions in a synthetic company scenario with database users with different access control levels
- show a baseline case of failure in the dashboard, which happens without aegis, and then success case with aegis, let the dashboard have the option to select to try the system as different users defined above to let judges test the solution themselves
- fancy dashboards showing agent tool calling changing stuff actions visualising it etc, and giving the judges the option to enable diable all the controls we have in place through the dashboard
- have a donecheck like classifier that checks the scope of the agent and whether or not the action being demanded by the user is possible for the agent or not
- scope of policy eengine define rules according to ocmpany and scneario we make the rubric itself
- end to end working pipeline scope
- how to make it pluggable and model agnostic

## Also open, from the MVP code review

- tool-result injection, multilingual, split-payload and malicious-redirect fixtures
- `PHONE` in `dlp.py` is loose enough that a spec sheet with a long run of digits and
  separators could label a page PII
- the runtime API and MCP enforcement adapter described in `BUILD_HANDOFF.md`
