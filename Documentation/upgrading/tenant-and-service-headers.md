---
title: Tenant and service headers follow Arc
description: AuthProxy now forwards the tenant as x-cratis-tenant-id and selects services by x-cratis-microservice, the names Arc uses by default, and strips both tenant headers from inbound requests.
---

AuthProxy now uses the header names Arc uses by default. An Arc application behind AuthProxy resolves its
tenant from the forwarded header with no tenancy configuration, and an Arc frontend that sets a
microservice is routed without further setup.

This is a breaking change for anything that reads `Tenant-ID` from a request AuthProxy forwards, which is
why it ships as a major release.

| | Before | Now |
|---|--------|-----|
| Tenant forwarded to the backend, and sent to `/.cratis/me` | `Tenant-ID` | `x-cratis-tenant-id` |
| Service selection header | `Service-ID` | `x-cratis-microservice` |
| Service selection query parameter | `?service=` | `?service=` (unchanged) |

## What breaks

A backend that reads the tenant from `Tenant-ID` no longer receives one. AuthProxy does not also send the
old name.

- **Arc applications** on their default tenancy settings now work with no configuration. If you set
  `options.UseHeaderTenancy("Tenant-ID")` as a workaround, remove it, or change it to `x-cratis-tenant-id`.
- **Other backends** reading `Tenant-ID` must read `x-cratis-tenant-id` instead.
- **A `/.cratis/me` endpoint** that reads the tenant header receives it as `x-cratis-tenant-id`.

## What keeps working

`Service-ID` is still accepted inbound and selects the service exactly as before, for routing and for the
per-service authorization requirements. `x-cratis-microservice` wins when a request carries both. The
`?service=` query parameter is unchanged. A client does not need to change to keep being routed. When a
request carries only `Service-ID`, AuthProxy adds `x-cratis-microservice` with the same value and leaves
`Service-ID` in place, so a backend that reads either still sees it.

## Inbound tenant headers are now stripped

Previously AuthProxy stripped an inbound `Tenant-ID` but not `x-cratis-tenant-id`. An Arc application with
its default tenancy settings behind AuthProxy therefore ignored the tenant AuthProxy resolved and took one
from the client, and the tenant decides the Chronicle namespace and the tenant-scoped read models.

AuthProxy now removes the tenant header under both names, `x-cratis-tenant-id` and `Tenant-ID`, from every
inbound request, whatever its casing, and again from the request it forwards. The only tenant a backend
receives is the one AuthProxy resolved itself, and a request with no resolved tenant reaches the backend
with none.

Every inbound header whose name begins `x-ms-client-principal` is also removed, not just the three that
AuthProxy writes, so `x-ms-client-principal-idp` and similar cannot be used to pass a claim to a backend.

If you have configured Arc with a different tenant header, for example `UseHeaderTenancy("x-tenant")`,
AuthProxy does not know about it and does not strip it, and it does not forward the tenant in it. Align Arc
with `x-cratis-tenant-id`; until you do, put a rule in the ingress above AuthProxy that removes the
header from client requests.

## What to do

1. Change anything that reads `Tenant-ID` from a forwarded request to read `x-cratis-tenant-id`.
2. Remove `UseHeaderTenancy("Tenant-ID")` from Arc applications behind AuthProxy.
3. Optionally, change clients and Arc frontends to send `x-cratis-microservice` instead of `Service-ID`.

See [Tenancy](../configuration/tenancy.md), [Services](../configuration/services.md#multiple-services) and
[Forwarded identity headers](../configuration/authentication.md#forwarded-identity-headers).
