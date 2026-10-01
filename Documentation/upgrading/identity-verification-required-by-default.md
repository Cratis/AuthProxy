---
title: Identity verification is required by default
description: Service.IdentityVerification now defaults to Required, which fails closed. This note lists what now denies and how to keep the previous BestEffort behavior.
---

`IdentityVerification` on a [service](../configuration/services.md) now defaults to `Required`. It used to
default to `BestEffort`.

This secure-default fix ships in a minor release. Services that need the previous enrichment-only behavior
can opt out explicitly without changing their endpoint.

## Why

Under `BestEffort` only an HTTP `403` from a service's `/.cratis/me` endpoint refused a caller. An
unreachable service, a timeout, any other failing status, or an empty, unparseable or negative body let the
request through. A gateway whose identity service is down was therefore the most permissive exactly when it
knew the least. `Required` closes that: only an explicit positive admits.

## What this affects

Only a service that **configures an identity-details endpoint**: it declares a `Backend` and has not set
`ResolveIdentityDetails` to `false`. A service with no backend, or with `ResolveIdentityDetails: false`, is
never called and is unaffected.

For an affected service that states no `IdentityVerification`, the following now return the `403` forbidden
page instead of forwarding the request:

| `/.cratis/me` on the service… | Before | Now |
|-------------------------------|--------|-----|
| is not implemented (`404`) | forwarded | **denied** |
| cannot be reached (DNS, connection refused, TLS) | forwarded | **denied** |
| does not answer within the timeout | forwarded | **denied** |
| answers any other non-`2xx` (`400`, `401`, `500`, `502`, `503`…) | forwarded | **denied** |
| answers `204`, or `200` with an empty or blank body | forwarded | **denied** |
| answers a body that is not valid JSON | forwarded | **denied** |
| answers JSON with no `isAuthorized` verdict | forwarded | **denied** |
| answers `"isAuthorized": false`, or contradicting verdicts | forwarded | **denied** |
| answers `403` | denied | denied |
| answers `200` with `"isAuthorized": true` | forwarded | forwarded |

Four consequences follow from the same change:

- **A bounded wait.** An unstated `IdentityVerificationTimeout` is now ten seconds instead of the ambient
  100-second HTTP client default. State a value to change it.
- **A tenant is needed to verify.** Identity is verified per user and tenant, so AuthProxy now refuses to
  start when any such service exists and `TenantResolutions` is empty. The message names the key. Declare a
  tenant resolution (`Specified` with a tenant ID is the single-tenant one), or opt the service out as below.
- **Callers with no resolved tenant are refused.** An authenticated request whose tenant does not resolve is
  denied rather than forwarded, except on [anonymous paths](../configuration/services.md#anonymous-paths)
  and AuthProxy's own sign-in, invite and registration surfaces.
- **A non-positive revalidation interval no longer remembers authorization in a cookie.** Previously,
  `Session.IdentityRevalidationInterval` set to zero or a negative value still produced a sealed record
  valid for ten minutes. With any `Required` service, no such record is written or reused. The independent
  `Session.IdentityResultCacheDuration` still applies (30 seconds by default); after that cache expires,
  AuthProxy asks the endpoints again. Set a positive `IdentityRevalidationInterval` to remember verified
  authorization, or explicitly select `BestEffort` for every affected service to keep the old fallback.

An affected service also stops being served while its identity endpoint is down. That is the intent.
Denials under `Required` log a warning naming the service, a bounded reason for the denial, and the
exact opt-out: `Cratis__AuthProxy__Services__<name>__IdentityVerification=BestEffort`. A missing resolved
tenant or exhausted identity-resolution wait produces one warning listing the Required services and
their opt-outs. A canceled request is an ordinary client disconnect and logs only a debug denial,
without an opt-out warning.

## Authorization cookies during upgrade

Required verification now accepts a sealed authorization cookie only if it was issued after every currently
Required participating service verified the caller. The cookie is bound to that service set; adding a
Required service or switching a service from `BestEffort` to `Required` forces verification again. The
in-memory result cache is also scoped to that set, so a cached `BestEffort` admission cannot become proof
of Required verification after a configuration reload. Older cookies and cookies issued under `BestEffort` cannot bypass verification,
including when Data Protection keys are preserved or older instances keep issuing cookies during a rolling
upgrade. The first request carrying such a cookie is checked again, rather than trusting its previous
revalidation window (ten minutes by default). This does not sign the user out unless verification denies
access and session termination is enabled. Explicit `BestEffort` deployments can still reuse older cookies.

## What to do

First check each service with a backend: does it answer `/.cratis/me` with `"isAuthorized": true` for
users who may enter? If so, nothing needs to change.

If a service only enriches the identity, or does not implement the endpoint, restore the previous behavior
for that service explicitly:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Services": {
        "reporting": {
          "Backend": { "BaseUrl": "http://reporting-api:8080/" },
          "IdentityVerification": "BestEffort"
        }
      }
    }
  }
}
```

The exact one-line environment setting is (replace `<name>` with the configured service name):

```bash
Cratis__AuthProxy__Services__<name>__IdentityVerification=BestEffort
```

For example: `Cratis__AuthProxy__Services__reporting__IdentityVerification=BestEffort`.
From an Aspire app host:

```csharp
authproxy.WithIdentityVerification("reporting", IdentityVerificationMode.BestEffort);
```

If the endpoint should never be called, set `ResolveIdentityDetails` to `false` instead. See
[Identity enrichment](../configuration/services.md#identity-enrichment) for the full behavior of each mode.
