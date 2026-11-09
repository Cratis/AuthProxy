---
title: Operator upgrade guide, 2.42 to 2.52
description: Version-by-version guide for operators moving AuthProxy from 2.42 to 2.52, covering trusted proxies, backend TLS, credential binding, token tenant binding and on-behalf settings.
---

This guide is for operators who run AuthProxy 2.42 and are moving to 2.52. It lists what each release changes,
the settings you must set before upgrading, and the settings you may turn on later. Every setting named here
is a server-side setting. No caller header or request option can change it.

Target **2.51.1 or later**. Version 2.51.0 changed the forwarded-headers default and 2.51.1 stopped back-channel
clients from keeping cookies, so a deployment that stops at an earlier 2.5x release is missing both.

## Before you upgrade

One change in this range needs action on most deployments, and the rest are opt-in.

| Action | Applies when | Section |
|--------|--------------|---------|
| Set `Ingress:TrustedProxies` (and `Ingress:ForwardLimit` for chained proxies) | AuthProxy runs behind an ingress, load balancer, CDN or mesh sidecar | [2.51.0](#2510-forwarded-headers-are-not-trusted-by-default) |
| Serve identity endpoints over HTTPS with a client certificate | You use forwarded-identity signing (2.44 or later) outside the `LocalDevelopment` profile | [2.45.0](#2450-and-2460-https-for-signed-hops) |
| Restart all replicas together with identical values | You enable `CredentialBinding` | [2.48.0](#2480-credential-binding) |
| Check that backends do not read identity or tenant headers on anonymous routes | A service declares `AnonymousPaths` | [2.50.1](#2501-anonymous-routes-carry-no-identity) |

Everything else below keeps its previous behavior until you turn it on.

## What changes in each version

| Version | Change | Operator action |
|---------|--------|-----------------|
| 2.43.0 | Optional per-service `SignInCallback` | None. Off until configured. |
| 2.44.0 | Optional per-service forwarded-identity signing; inbound envelope headers removed | None unless you adopt signing. |
| 2.45.0 | Backend TLS settings; signed hops must use HTTPS | Only if signing is configured. |
| 2.46.0 | Signing and HTTPS extend to back-channel calls | Only if signing is configured. |
| 2.47.0 | Client-supplied forwarded-identity headers are always removed | Check backends that read identity from caller-set headers. |
| 2.48.0 | Credentials are bound to their tenant; optional resource and environment binding | None required. Enabling the binding signs everyone out once. |
| 2.49.0 | `BackendTls:RequireTlsOnIdentityHops` | Opt-in. |
| 2.50.0 | `Authentication:ExternalTokenTenantBinding` | Opt-in. Recommended for multi-tenant external issuers. |
| 2.50.1 | Anonymous routes drop forwarded identity; callback paths are matched exactly | Check anonymous routes. |
| 2.51.0 | Forwarded headers are ignored unless trusted proxies are configured | **Required behind a proxy.** |
| 2.51.1 | Back-channel clients no longer store or replay cookies | None. |
| 2.52.0 | `OnBehalf:OmitActorHeaderOnBackChannelCalls` | Opt-in. |

## 2.43.0: sign-in callbacks

A service can declare `SignInCallback` (`Path`, `Interval`, `Timeout`, `Secret`). AuthProxy then posts a
`SignedIn` callback after a sign-in and a `Returned` callback on the first request of an existing session,
then at most once per interval for each user and service. Delivery is best effort and never blocks the user's
request. A service without the section receives nothing. See [sign-in callbacks](../configuration/sign-in-callback.md).

## 2.44.0: forwarded-identity signing

A service can sign the identity it forwards with the Arc v1 envelope by setting
`Cratis:AuthProxy:Services:<name>:ForwardedIdentity` (`Audience`, `KeyId`, `SecretBase64`). Nothing signs until
you configure it. When you do, startup refuses an unusable block and refuses the same key shared between
different backends. Provide `SecretBase64` from a secret store, never from committed configuration.

Two behavior changes apply to every deployment:

- Inbound forwarded-identity envelope headers are removed before a request is forwarded.
- Bearer routes set the service header from the route's own service rather than a caller-supplied value.

From Aspire, `WithSignedForwardingTo(backend)` pairs AuthProxy with an Arc backend. See
[Forwarded identity signing](../configuration/forwarded-identity-signing.md).

## 2.45.0 and 2.46.0: HTTPS for signed hops

2.45.0 adds the `Cratis:AuthProxy:BackendTls` settings. AuthProxy can present a client certificate to
backends and trust a private CA bundle, both from mounted PEM files that reload without a restart. It also adds
`Cratis:AuthProxy:Profile`, whose `LocalDevelopment` value is for developer machines only.

**Deployments that do not configure forwarded-identity signing are unaffected by 2.45.0 and 2.46.0.** If you do
sign, outside the `LocalDevelopment` profile:

- Every hop that receives signed identity (service backends, signed frontends and tenant-list endpoints) must
  use HTTPS and a configured client certificate, or AuthProxy refuses to start. 2.45.0 introduces this.
- Sign-in callbacks to a signed service carry the envelope and are not sent if signing fails. 2.46.0 introduces this.
- On-behalf, invitation, link and sign-in notification calls use the backend TLS client settings and must use HTTPS.
- The client-credentials, capability, tenant and user-token verification endpoints must use HTTPS, checked at
  startup and again before each call.

Serve every endpoint named in a startup validation error over HTTPS before you upgrade. See
[Backend TLS](../configuration/backend-tls.md).

## 2.47.0: client-supplied identity headers are removed

AuthProxy now removes every client-supplied forwarded-identity context header. Header names are compared
without regard to case or to `_` versus `-`. A backend therefore only sees identity headers AuthProxy set
itself. Routing headers such as `x-cratis-microservice` are still forwarded.

A backend that depended on a caller setting an identity header itself must obtain identity from the headers
AuthProxy forwards instead.

## 2.48.0: credential binding

AuthProxy keeps sessions and tokens bound to the tenant they were issued for. This applies without any setting:

- A request whose session or token is bound to a different tenant than the one it addresses is refused with `403`
  before tenant selection, and nothing is forwarded.
- When tenant selection is configured, a tenant addressed by host, sub-host or route is confirmed against the
  person's memberships before forwarding.
- On bearer routes, a token that names a different tenant than the one addressed is refused with `403`.
  `Specified` and `Default` tenants do not override the token tenant.
- Starting an ordinary sign-in after an abandoned registration or invitation clears the pending flow.

You may also bind credentials to the deployment:

```json
{
  "Cratis": {
    "AuthProxy": {
      "CredentialBinding": {
        "Resource": "orders-prod",
        "Environment": "production"
      }
    }
  }
}
```

`Resource` and `Environment` default to empty (no binding). Sessions, selection cookies and AuthProxy-issued
tokens issued for another resource or environment stop working. Enabling or changing either value **signs
everyone out once**, so restart all replicas together with identical values. A bearer route can add
`EnvironmentClaimType`, which requires `CredentialBinding:Environment`.

When replicas or environments share a Data Protection key ring, set `CredentialBinding:Resource`. AuthProxy logs a
startup warning when a shared key ring has no resource. See
[Credential binding](../configuration/tenancy.md#credential-binding) and
[Data protection](../configuration/data-protection.md).

## 2.49.0: require HTTPS on identity hops

`Cratis:AuthProxy:BackendTls:RequireTlsOnIdentityHops` is off by default. When set to `true`, startup refuses any
identity-bearing backend, callback, notifier or verifier target that is not HTTPS, outside local development.
It does not require a client certificate for unsigned hops. Inventory every identity-bearing URL first, then
enable it in a test deployment before production. From Aspire, call `WithRequiredTlsOnIdentityHops()`. See
[Enable for an existing deployment](../configuration/backend-tls.md#enable-for-an-existing-deployment).

## 2.50.0: bind external tokens to a tenant

`Cratis:AuthProxy:Authentication:ExternalTokenTenantBinding` is off by default. Turn it on when external
issuers sign tokens for more than one tenant:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Authentication": {
        "ExternalTokenTenantBinding": {
          "Require": true,
          "TenantClaimType": "tid",
          "TenantMapping": { "external-directory-a": "tenant-a" }
        }
      }
    }
  }
}
```

With `Require` set, a token is accepted only if it carries exactly one value for the tenant claim, optionally
mapped to a tenant, and a token whose tenant differs from the addressed tenant is refused with `403`.
Startup validation rejects incomplete settings, and AuthProxy logs a warning when external bearer tokens are
configured without the binding. See
[Bind external tokens to a tenant](../configuration/authentication.md#bind-external-tokens-to-a-tenant).

## 2.50.1: anonymous routes carry no identity

On routes configured as anonymous, AuthProxy now removes forwarded identity, tenant, authorization, on-behalf and
signature material before the request reaches the backend, including copies the caller supplied. This applies
to authenticated sessions and bearer-token callers as well. A backend that expects identity on a path in
`AnonymousPaths` must serve that path from a route that is not anonymous. A path that must still receive the
caller's own `Authorization` header can be listed in `PassCallerAuthorizationPaths`. See
[Anonymous paths](../configuration/services.md#anonymous-paths).

Authentication bootstrap path matching also accepts only the configured callback paths, not any path starting
with `/signin-`. A deployment that relied on an unconfigured `/signin-*` path must configure that callback path.

## 2.51.0: forwarded headers are not trusted by default

This is the change most likely to alter an unchanged deployment. In the default `Configured` mode, an empty
`Cratis:AuthProxy:Ingress:TrustedProxies` list now means `X-Forwarded-For` and `X-Forwarded-Proto` are ignored
from every caller. Earlier versions accepted them from everyone. AuthProxy still starts, but it uses the
connection's client address and scheme. That affects the address in sign-in notifications, the `Secure` flag
on cookies and the public origin used for logout.

AuthProxy logs a startup warning when no trusted proxies are configured, and a rate-limited warning when
requests arrive with forwarded headers that are being ignored. `ASPNETCORE_FORWARDEDHEADERS_ENABLED` does not
bypass the setting, and you should leave it unset.

Behind an ingress or load balancer, declare the peers AuthProxy sees directly in front of it:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Ingress": {
        "TrustedProxies": [ "10.0.0.0/8", "203.0.113.7" ],
        "ForwardLimit": 1
      }
    }
  }
}
```

The environment forms are `Cratis__AuthProxy__Ingress__TrustedProxies__0` (and `__1`, and so on) and
`Cratis__AuthProxy__Ingress__ForwardLimit`. From Aspire, use `WithTrustedProxies(...)` and `WithForwardLimit(n)`.

- Each entry is an IP address or a CIDR range. An entry that cannot be parsed fails startup.
- Declare the addresses AuthProxy sees as the peer, not your users' addresses.
- `ForwardLimit` defaults to `1`. Set it to the number of proxy hops you actually have, and include every
  intermediate hop in `TrustedProxies`. Too high a value reports an address the outermost caller chose.
- If only your own ingress can reach AuthProxy and you cannot enumerate it, set
  `Cratis:AuthProxy:Ingress:Mode` to `TrustAny` explicitly. Use this only when a network boundary already
  restricts who can connect.

The Aspire integration defaults to `TrustAny` for local run mode only, and only when no trusted-proxy setting is
given. Published deployments use the secure default. See
[Trusted proxies](../configuration/trusted-proxies.md#upgrading-a-deployment-with-no-trusted-proxies).

## 2.51.1: back-channel clients do not keep cookies

Outbound back-channel HTTP clients no longer store or replay cookies set by the services they call. This covers
proxying, admission, bearer routes, invites, client-credentials verification and the OAuth, OIDC and JWT back
channels. A response cookie can no longer carry over to later requests made for other callers. Documented
callback identity headers are unchanged. No setting controls this, and no configuration change is needed.
A backend that kept state by setting a cookie on an AuthProxy back-channel call must carry that state in the
request itself.

## 2.52.0: omit the on-behalf actor header

Applications that use Arc's signed forwarded-identity scheme can stop AuthProxy from sending the separate actor
header on on-behalf calls. Set `Cratis:AuthProxy:OnBehalf:OmitActorHeaderOnBackChannelCalls` to `true`
(environment variable `Cratis__AuthProxy__OnBehalf__OmitActorHeaderOnBackChannelCalls`). It defaults to `false`.

The `x-cratis-on-behalf-actor` header is then left out of on-behalf grant checks and session started and ended
notifications. The attestation is unchanged. Enable it only when the receiver fully verifies the attestation,
including replay checks, and reads the actor from it. See
[On-behalf sessions](../configuration/on-behalf-sessions.md#what-the-application-implements).

## Recommended end state

1. Run 2.51.1 or later.
2. Set `Ingress:TrustedProxies` and a correct `Ingress:ForwardLimit`, or an explicit `TrustAny` behind a closed network.
3. Enable `BackendTls:RequireTlsOnIdentityHops` once every identity-bearing endpoint serves HTTPS.
4. Enable `Authentication:ExternalTokenTenantBinding` when external issuers cover several tenants.
5. Set `CredentialBinding` values when sessions or tokens must not cross resources or environments.
6. Enable `OnBehalf:OmitActorHeaderOnBackChannelCalls` once receivers read the actor from the attestation.

Check the startup log after each step. Warnings name the setting that is missing.
