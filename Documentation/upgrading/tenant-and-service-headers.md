---
title: Tenant and service headers follow Arc
description: AuthProxy forwards both current and legacy tenant and service headers during the transition and strips client-supplied tenant headers.
---

AuthProxy now also forwards the header names Arc uses by default. Existing backends continue to receive
`Tenant-ID` and `Service-ID`, so this is a compatible transition in a minor release, not a rename.

| | Before | Now |
|---|--------|-----|
| Tenant forwarded to the backend, and sent to `/.cratis/me` | `Tenant-ID` | Both `x-cratis-tenant-id` and `Tenant-ID`, with the same resolved value |
| Service selection headers | `Service-ID` | Both `x-cratis-microservice` and `Service-ID` accepted; the current name wins |
| Service identifier forwarded to the backend | The supplied service header, if any | Both `x-cratis-microservice` and `Service-ID`, identifying the service selected by the route |
| Service selection query parameter | `?service=` | `?service=` (unchanged) |

## Compatibility and deprecation

No configuration change is needed to keep reading the legacy headers. Studio, Direct, and other existing
backends that read `Tenant-ID` still receive the tenant AuthProxy resolved. Identity endpoints receive
both tenant names too.

Forwarding `Tenant-ID` and `Service-ID` is deprecated and will be removed in a future major release.
Move backends to `x-cratis-tenant-id` and `x-cratis-microservice` before that release. This deprecation
concerns forwarding; `Service-ID` is still accepted inbound, and `x-cratis-microservice` is now accepted too.

Arc applications on their default tenancy settings now work without extra configuration. If you set
`options.UseHeaderTenancy("Tenant-ID")` as a workaround, you can remove that one line. Keeping it also
continues to work during the transition.

## Service selection

`Service-ID` is still accepted inbound for routing and per-service authorization.
`x-cratis-microservice` wins when a request carries both. The `?service=` query parameter remains the
fallback when no header route matches, including when the header names an unknown service. Per-service
authorization follows the matched route too, so an unknown header cannot bypass a query-selected service's
claim requirements. Both forwarded headers carry the configured destination name with its original casing
(for example, `Studio`, not `studio`), even when a caller's selector loses to an anonymous-path route or the
single-service catch-all. Query-only requests also receive
both headers. Requests to the single-service catch-all now receive both headers even with no selector.

Arc's default WebSocket and SSE observable connections use `?x-cratis-microservice=`, which AuthProxy does
not route on yet. For multi-service deployments, set `Globals.microserviceWSQueryArgument = 'service';`
in the Arc frontend to use the supported `?service=` query parameter. HTTP requests already use the
supported `x-cratis-microservice` header. This query-argument mismatch remains tracked in
[issue #154](https://github.com/Cratis/AuthProxy/issues/154).

## Inbound tenant headers are stripped

Previously AuthProxy stripped an inbound `Tenant-ID` but not `x-cratis-tenant-id`. An Arc application with
its default tenancy settings behind AuthProxy therefore ignored the tenant AuthProxy resolved and took one
from the client, and the tenant decides the Chronicle namespace and the tenant-scoped read models.

AuthProxy now removes both `x-cratis-tenant-id` and `Tenant-ID` from every inbound request, whatever their
casing, and again from the forwarded request. It then writes the resolved value under both names. A
request with no resolved tenant reaches the backend with neither tenant header, never a client value.

Every inbound header whose name begins `x-ms-client-principal` is also removed, not just the three that
AuthProxy writes, so `x-ms-client-principal-idp` and similar cannot be used to pass a claim to a backend.

If you have configured Arc with a different tenant header, for example `UseHeaderTenancy("x-tenant")`,
AuthProxy does not know about it and does not strip it or forward the tenant in it. Align Arc with
`x-cratis-tenant-id`; until you do, put a rule in the ingress above AuthProxy that removes that header
from client requests.

## What to do

1. Move backends that read `Tenant-ID` or `Service-ID` to the matching `x-cratis-*` names before the future major release.
2. Remove `UseHeaderTenancy("Tenant-ID")` from Arc applications behind AuthProxy if you want to use Arc's defaults.
3. Optionally, change HTTP clients and Arc frontends to send `x-cratis-microservice` instead of `Service-ID`.
4. In multi-service deployments using Arc observable connections, set `Globals.microserviceWSQueryArgument = 'service';`.

See [Tenancy](../configuration/tenancy.md), [Services](../configuration/services.md#multiple-services) and
[Forwarded identity headers](../configuration/authentication.md#forwarded-identity-headers).
