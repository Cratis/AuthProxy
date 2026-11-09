---
title: Selected tenant and upstream headers
description: Check AuthProxy upgrade behavior for selected tenants, proxy cookies and caller Authorization headers, including explicit forwarding configuration.
---

## Authentication selection: behavior change

**Protected requests carrying both a bearer token and an AuthProxy session cookie now return `401`,
even when `CallerAuthorizationHeader` is `Forward`. Invalid or expired authentication also returns `401`
without falling back to another authentication type.** Failed session cookies are expired in that response;
local logout, login selection, and provider sign-in remain reachable so the browser can recover.

Browser clients using the AuthProxy session must stop attaching their own bearer token to those requests.
If the service needs a delegated token, configure [`AccessToken`](../configuration/services.md#access-token)
in AuthProxy instead. Clients using their own bearer token must omit the AuthProxy session cookie; for browser
`fetch` calls, use `credentials: 'omit'` on those bearer-authenticated requests rather than sending both.
Keep session-cookie requests cookie-authenticated only, and send users through `/.cratis/login/{scheme}`
when a session has expired. Anonymous routes retain their existing behavior.

## The caller's Authorization header

By default, `CallerAuthorizationHeader` on a [service](../configuration/services.md#caller-authorization-header)
is `Default`:

- On a request authenticated by the AuthProxy session, the `Authorization` header the caller sent is **removed**
  before the request reaches the service.
- On a protected request authenticated by its own bearer token without a session cookie, the header is **kept**.
- On an [anonymous path](../configuration/services.md#anonymous-paths), the header is always **removed**.

A token AuthProxy obtains for the service through `AccessToken`, and the bearer token of a caller AuthProxy itself
authenticated, are always forwarded.

`Forward` can retain a non-bearer caller header on session requests. It does not permit bearer-plus-session
requests. For a service that explicitly needs that non-bearer header:

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

In default `Configured` mode with no `TrustedProxies`, AuthProxy now ignores forwarded headers from every
caller and retains the connection's client address and scheme. It logs a startup warning and one warning per
process when forwarded headers are received in that mode.

Behind an ingress, set `Cratis:AuthProxy:Ingress:TrustedProxies` and
`Cratis:AuthProxy:Ingress:ForwardLimit` for your deployment. To retain allow-all behavior when only your ingress
can connect, explicitly select `Cratis:AuthProxy:Ingress:Mode=TrustAny`. See the
[trusted-proxy upgrade note](../configuration/trusted-proxies.md#upgrading-a-deployment-with-no-trusted-proxies).
Local Aspire run mode supplies `TrustAny` only when no boundary settings were supplied; publish mode is unchanged.
