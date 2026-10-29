---
title: Selected tenant and upstream headers
description: A selected tenant is confirmed for the signed-in account before it is forwarded, services stop receiving AuthProxy's own cookies, and the caller's Authorization header is removed on session requests by default.
---

## The caller's Authorization header

By default, `CallerAuthorizationHeader` on a [service](../configuration/services.md#caller-authorization-header)
is `Default`:

- On a request authenticated by the AuthProxy session, the `Authorization` header the caller sent is **removed**
  before the request reaches the service.
- On a request without a session, such as one to an [anonymous path](../configuration/services.md#anonymous-paths),
  the header is **kept**.

A token AuthProxy obtains for the service through `AccessToken`, and the bearer token of a caller AuthProxy itself
authenticated, are always forwarded.

A service that relied on receiving the caller's own header on session requests opts in to `Forward`:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Services": {
        "portal": {
          "Backend": { "BaseUrl": "http://portal-api:8080/" },
          "CallerAuthorizationHeader": "Forward"
        }
      }
    }
  }
}
```

`Strip` removes the header from every request the service receives. The environment variable form is
`Cratis__AuthProxy__Services__<name>__CallerAuthorizationHeader=Forward`.

## Selected tenant

The `.cratis-tenant` cookie is now signed and tied to the account that selected it. A tenant is forwarded only after
AuthProxy has confirmed it for the signed-in account, and that confirmation happens on every request that carries a
selected tenant, including anonymous, invitation and registration paths.

- Cookies written by an earlier version are confirmed against `TenantsEndpoint` on first use and reissued, one call
  per user after the upgrade. Nobody has to select again.
- When `TenantsEndpoint` cannot answer, a tenant that has not been confirmed within
  `Session.TenantRevalidationInterval` is not forwarded: a normal request receives `503`, and an anonymous or
  registration path continues with no tenant. Expect `503` for users whose window lapsed during an outage of that
  endpoint.
- `TenantRevalidationInterval` set to `0` now means the signed selection is trusted until it changes.
- Deployments with more than one replica need a shared Data Protection key ring for the signed cookie, as they
  already do for sessions.
- Users whose principal names no identity provider must sign in again when more than one provider is configured, because a user identifier alone does not name one account.
- There is no setting to keep the previous behavior of forwarding a tenant that was not confirmed.

## Tenant identifiers

Every [tenant resolution strategy](../configuration/tenancy.md) applies the same rule to the value it resolves:
letters, digits and `-._~`, at most 256 characters. A tenant identifier outside that rule no longer resolves. The
`Claim` strategy reads the claim from the signed-in user only. The tenant verification URL escapes the identifier.

## AuthProxy cookies

AuthProxy's own cookies, the session cookie with its chunks and the `.cratis-*` cookies, are no longer forwarded to
services. Every other cookie arrives unchanged and in order. A service that read one of AuthProxy's cookies must stop.

## Forwarded headers

With no `TrustedProxies` configured, AuthProxy logs one warning per process when a caller at a public address sends
`X-Forwarded-For` or `X-Forwarded-Proto`. Behavior is unchanged; set `Cratis:AuthProxy:Ingress:TrustedProxies`
as described in [trusted proxies](../configuration/trusted-proxies.md).
