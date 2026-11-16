---
area: Operations
type: Added
---
- OTLP audit export gives each record an event name and standard OpenTelemetry attributes
  ([#368](https://github.com/public/wicket/issues/368)). Egress decisions get HTTP conventions
  (`http.request.method`, `server.address`, `url.path`), model calls get the GenAI conventions
  (`gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.usage.*`), and tool calls and approvals
  are mapped too. Refusals and failed model calls are `WARN`, with `error.type`. The body is still
  the hash-chained record. Model-call audit records now name the zone's provider.
