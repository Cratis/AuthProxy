---
title: "Telemetry"
description: "AuthProxy emits OpenTelemetry traces and metrics about sign-ins, identity, tenancy, invitations and bearer tokens, exported only when you configure an OTLP endpoint."
---

# Telemetry

AuthProxy emits OpenTelemetry **traces** and **metrics** under the instrumentation scope `Cratis.AuthProxy`,
and exports redacted **logs** through the shared setup.
It is off until you point it somewhere: with no `OTEL_*` variable set nothing is exported and the proxy
behaves exactly as before.

Setup uses the shared `Cratis.OpenTelemetry` package, so the standard OpenTelemetry environment variables
apply and need no AuthProxy-specific configuration.

---

## Turning it on

| Variable | Effect |
|----------|--------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Where to send traces, metrics and logs over OTLP. Unset means nothing is exported. |
| `OTEL_EXPORTER_OTLP_HEADERS` | Headers for the exporter, such as an API key. |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `grpc` or `http/protobuf`. |
| `OTEL_SERVICE_NAME` | The `service.name` of the proxy. Defaults to `cratis-authproxy`. |
| `OTEL_RESOURCE_ATTRIBUTES` | Extra resource attributes, such as `deployment.environment=prod`. |

Azure Monitor and Application Insights accept OTLP through an OpenTelemetry Collector (or the Azure Monitor
collector exporter): point `OTEL_EXPORTER_OTLP_ENDPOINT` at the collector and let it forward to Application
Insights.

---

## Trace context

The W3C `traceparent` and `tracestate` headers a caller sends continue through the proxy to the service, so a
request is one trace from the caller to your application. The W3C `baggage` header and the legacy
`Correlation-Context` header are **not** forwarded: what a caller attaches to a request never reaches a service.

---

## Spans

| Span | Covers |
|------|--------|
| `cratis.authproxy.sign_in.notify` | Telling the application a sign-in completed. |
| `cratis.authproxy.identity.resolve` | Resolving the identity details of a signed-in caller (`/.cratis/me`). |
| `cratis.authproxy.tenant.resolve` | Resolving the tenant of a request. |
| `cratis.authproxy.invite.exchange` | Exchanging an invitation for a completed sign-in. |
| `cratis.authproxy.bearer.validate` | Validating the access token presented on a bearer route. |

## Metrics

| Metric | Unit | Attribute | Counts |
|--------|------|-----------|--------|
| `cratis.authproxy.sign_ins` | `{sign_in}` | `cratis.authproxy.sign_in.outcome` | Completed sign-ins. |
| `cratis.authproxy.identity.denials` | `{denial}` | `cratis.authproxy.identity.denial_reason` | Identity verifications that refused the caller. |
| `cratis.authproxy.identity.cache.requests` | `{request}` | `cratis.authproxy.identity.cache.result` | Identity cache lookups, `hit` or `miss`. |
| `cratis.authproxy.bearer.validations` | `{validation}` | `cratis.authproxy.bearer.outcome` | Bearer token validations. |
| `cratis.authproxy.invite.exchanges` | `{exchange}` | `cratis.authproxy.invite.outcome` | Invitation exchanges. |
| `cratis.authproxy.upstream.errors` | `{error}` | `error.type` | Requests that could not be forwarded to a service. |

The names are constants on `Cratis.AuthProxy.Telemetry.WellKnownTelemetryNames`.

---

## What is never recorded

Every attribute AuthProxy adds is a small, closed set of lowercase words. No token, claim value, subject,
email, cookie, secret, URL or tenant identifier is ever added as a span name, span attribute, or metric
attribute, so a telemetry backend never holds a credential or a person.

The standard ASP.NET Core and HTTP client instrumentation that comes with the shared setup also records
requests, so AuthProxy redacts what it records before any exporter sees it:

| Where | Redacted |
|-------|----------|
| Incoming request spans | The query string is never recorded, so a sign-in callback's `code` and `state` never appear. A path under `/invite` is recorded as `/invite/{token}`. The host (`server.address`, which is the tenant under subdomain tenancy) and the full URL are never recorded. |
| Outgoing request spans | Full URLs (`url.full`, `http.url`), paths, queries and destination hosts (`server.address`, `http.host`, `net.peer.name`, `network.peer.address`, `dns.question.name`) and destination ports are removed, including on failed calls. |
| Exceptions | `exception.*` span and event attributes and status descriptions are removed on every activity. Exception events, including native .NET HTTP client events, retain only their name and timestamp, not their payload. Span error status is kept. |
| Exported logs | Only metadata is exported: timestamp, severity, category, event ID and trace correlation. Every body and formatted message becomes `Log details redacted`; structured attributes, exceptions and scopes are excluded, at all log levels. This includes tenant-verification failures, bearer tenant refusals and Debug identity-endpoint URLs. The hosting, routing, Kestrel, reverse proxy and HTTP client loggers are still excluded below `Warning`. Local console messages retain their original details. |
| HTTP client metrics | Only `http.request.method`, `http.response.status_code`, `error.type`, `network.protocol.version`, `url.scheme` and `http.connection.state` are retained. The host the proxy called (`server.address`, `dns.question.name`) is not a metric attribute, because it can carry a tenant. |

Sanitization runs on completed activities before exporter queuing, not just during HTTP enrichment.
If path redaction throws, all span attributes are discarded; the span and its error status can still be
exported. Incoming `url.full` and `http.url` are explicitly removed. Standard HTTP method, response status,
timing and trace correlation remain available when redaction succeeds. Log event IDs and categories help
locate the original console diagnostics; exported logs deliberately do not include their detailed messages.
Resource attributes supplied through `OTEL_RESOURCE_ATTRIBUTES` are operator-controlled and are not sanitized;
do not put credentials or tenant identifiers in them.

The path of any other incoming request is recorded as it arrived. Paths that your application's own routes
use to carry a secret are your application's to keep out of its URLs; to hide them, drop the request spans
in your collector.
