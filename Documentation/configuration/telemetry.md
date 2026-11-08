---
title: "Telemetry"
description: "AuthProxy emits OpenTelemetry traces and metrics about sign-ins, identity, tenancy, invitations and bearer tokens, exported only when you configure an OTLP endpoint."
---

# Telemetry

AuthProxy emits OpenTelemetry **traces** and **metrics** under the instrumentation scope `Cratis.AuthProxy`.
It is off until you point it somewhere: with no `OTEL_*` variable set nothing is exported and the proxy
behaves exactly as before.

Setup uses the shared `Cratis.OpenTelemetry` package, so the standard OpenTelemetry environment variables
apply and need no AuthProxy-specific configuration.

---

## Turning it on

| Variable | Effect |
|----------|--------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Where to send traces and metrics over OTLP. Unset means nothing is exported. |
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
request is one trace from the caller to your application. The W3C `baggage` header is **not** forwarded:
what a caller attaches to a request never reaches a service.

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
| `cratis.authproxy.sign_in.count` | `{sign_in}` | `cratis.authproxy.sign_in.outcome` | Completed sign-ins. |
| `cratis.authproxy.identity.denials` | `{denial}` | `cratis.authproxy.identity.denial_reason` | Identity verifications that refused the caller. |
| `cratis.authproxy.identity.cache.requests` | `{request}` | `cratis.authproxy.identity.cache.result` | Identity cache lookups, `hit` or `miss`. |
| `cratis.authproxy.bearer.validations` | `{validation}` | `cratis.authproxy.bearer.outcome` | Bearer token validations. |
| `cratis.authproxy.invite.exchanges` | `{exchange}` | `cratis.authproxy.invite.outcome` | Invitation exchanges. |
| `cratis.authproxy.upstream.errors` | `{error}` | `error.type` | Requests that could not be forwarded to a service. |

The names are constants on `Cratis.AuthProxy.Telemetry.WellKnownTelemetryNames`.

---

## What is never recorded

Every attribute value is a small, closed set of lowercase words. No token, claim value, subject, email,
cookie, secret, URL or tenant identifier is ever a span name, span attribute, or metric attribute, so a
telemetry backend never holds a credential or a person.
