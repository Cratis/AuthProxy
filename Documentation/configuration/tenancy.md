---
title: "Tenancy"
description: "AuthProxy resolves a tenant ID from each request and forwards it to downstream services, and prevents clients from choosing their own tenant."
---

# Tenancy

AuthProxy resolves a **tenant ID** string from each incoming request and stores it in the request context.
Downstream services receive the resolved tenant ID under both `x-cratis-tenant-id` and `Tenant-ID`.
[Arc](/arc/) resolves its tenant from `x-cratis-tenant-id` by default, so an Arc application behind AuthProxy
needs no tenancy configuration. Legacy `Tenant-ID` forwarding is deprecated and will be removed in a
future major release; move backends to `x-cratis-tenant-id`.

In Cratis products, the tenant is what people see as a workspace. [Organization, workspace and namespace](/concepts/organization-workspace-namespace/) explains how a tenant relates to the customer's organization and to the Chronicle namespace that stores its data.

A client cannot choose the tenant a backend sees. AuthProxy strips an inbound `x-cratis-tenant-id` and
the legacy `Tenant-ID` header, and writes back only the tenant it resolved itself under both names. Earlier
releases sent only `Tenant-ID`; see [Upgrading](../upgrading/tenant-and-service-headers.md).

---

## Tenant resolution strategies

Resolution strategies run **in order** until one strategy resolves a tenant.
Configure them under `Cratis:AuthProxy:TenantResolutions`:

```json
{
  "Cratis": {
    "AuthProxy": {
      "TenantResolutions": [
        { "Strategy": "Host" },
        { "Strategy": "Claim", "Options": { "ClaimType": "tid" } }
      ]
    }
  }
}
```

### Available strategies

| Strategy | Description |
|----------|-------------|
| `Host` | Uses the request host and matches it against configured tenant `Domains` / `SourceIdentifiers`. |
| `Claim` | Reads a claim value from the authenticated user and matches it against configured tenant `SourceIdentifiers`. |
| `Route` | Extracts a source identifier from the request path by regex and matches it against configured tenant `SourceIdentifiers`. |
| `Specified` | Resolves directly to a fixed tenant ID string from configuration. |
| `Default` | Resolves directly to a fallback tenant ID string from configuration. |
| `SubHost` | Resolves directly from subhost convention, for example `acme.example.com` -> `acme`. |
| `Selection` | Resolves from the selected-tenant cookie set by the tenant-selection page flow. |

---

## Claim strategy options

```json
{
  "Strategy": "Claim",
  "Options": {
    "ClaimType": "tid"
  }
}
```

If `ClaimType` is omitted, the `http://schemas.microsoft.com/identity/claims/tenantid` claim is read. The claim is read from the signed-in user only; a principal header sent by the caller is never used.

Every strategy applies the same rule to the value it resolves: letters, digits and `-._~`, at most 256 characters. A value outside the rule does not resolve, and the tenant verification URL escapes the identifier it is given.

This is also how you resolve a tenant carried on an AuthProxy-issued client-credentials bearer token —
point `ClaimType` at `cratis/tenant`. See
[Resolving a tenant from the verification response](authentication.md#resolving-a-tenant-from-the-verification-response).

---

## Route strategy options

```json
{
  "Strategy": "Route",
  "Options": {
    "Pattern": "^/tenant/(?<sourceIdentifier>[^/]+)"
  }
}
```

The regex must expose a named group called `sourceIdentifier`.

---

## Specified strategy options

```json
{
  "Strategy": "Specified",
  "Options": {
    "TenantId": "acme"
  }
}
```

---

## Default strategy options

```json
{
  "Strategy": "Default",
  "Options": {
    "TenantId": "lobby"
  }
}
```

---

## SubHost strategy options

```json
{
  "Strategy": "SubHost",
  "Options": {
    "ParentHost": "example.com",
    "VerificationUrlTemplate": "https://platform.example.com/internal/tenants/{tenantId}"
  }
}
```

| Property | Type | Description |
|----------|------|-------------|
| `ParentHost` | `string` | Parent host suffix used to extract the tenant ID from the request host. |
| `VerificationUrlTemplate` | `string` | Optional strategy-specific verification URL template. Overrides the global `TenantVerification.UrlTemplate` for this strategy. |

### How SubHost resolution works

The strategy strips the configured `ParentHost` suffix from the incoming request host to derive the tenant ID.

Given `ParentHost: "example.com"`:

| Request host | Resolved tenant ID | Notes |
|---|---|---|
| `acme.example.com` | `acme` | Single-segment subhost — resolved successfully. |
| `contoso.example.com` | `contoso` | Single-segment subhost — resolved successfully. |
| `foo.bar.example.com` | — | Multi-segment subhost rejected — not resolved. |
| `example.com` | — | No subhost present — not resolved. |
| `other.com` | — | Host does not end with `.example.com` — not resolved. |

The resolved subhost string becomes the tenant ID directly.
**No `Tenants` dictionary lookup is performed** — unlike `Host`, `Claim`, and `Route` strategies, SubHost does not match a source identifier against a pre-configured list.
This is intentional: SubHost is designed for environments where tenants are provisioned dynamically (for example SaaS platforms where each customer gets their own subdomain).

### SubHost and a shared session cookie

`Session:CookieDomain` cannot be combined with a `SubHost` resolution: AuthProxy refuses to start. The host-only
session cookie is what keeps a session for one tenant off the next tenant's host, and a cookie shared across the
domain would send it to every tenant. See
[Why the cookie domain is refused with SubHost tenancy](one-proxy-several-hosts.md#why-the-cookie-domain-is-refused-with-subhost-tenancy).

### SubHost and authentication callbacks

For interactive authentication flows, AuthProxy stores SubHost strategy metadata in protected authentication `state` when it issues the provider challenge. On callback, AuthProxy restores this metadata and redirects to the tenant subhost.

This enables a shared callback endpoint (for example `auth.cratis.studio`) while returning the user to the original tenant host (for example `nova.cratis.studio`).

Because there is no registry lookup to prove the tenant exists, you should configure `VerificationUrlTemplate` to have AuthProxy call your back-end to confirm the tenant is valid before forwarding the request:

```json
{
  "Strategy": "SubHost",
  "Options": {
    "ParentHost": "example.com",
    "VerificationUrlTemplate": "https://internal-api.example.com/tenants/{tenantId}"
  }
}
```

AuthProxy replaces `{tenantId}` with the resolved subhost value and expects a `200` response.
Any other response causes the request to be rejected with `tenant-not-found.html`.
See [Tenant verification](#tenant-verification) for full response handling details.

---

## Selection strategy options

```json
{
  "Strategy": "Selection",
  "Options": {
    "TenantsEndpoint": "https://platform.example.com/api/tenants/selectable"
  }
}
```

| Property | Type | Description |
|----------|------|-------------|
| `TenantsEndpoint` | `string` | Absolute URL for the endpoint that returns selectable tenants for the current authenticated user. Expected response shape is an array of `{ "id": "...", "name": "..." }` objects. |

When this strategy is configured and no `.cratis-tenant` cookie exists yet, AuthProxy calls
`TenantsEndpoint`, sets the `.cratis-tenants` cookie, and serves `select-tenant.html`.
The page links back to `/.cratis/select-tenant?tenantId=<id>&returnUrl=<path>`, and AuthProxy validates
the selected tenant against the endpoint response before writing the `.cratis-tenant` cookie.

If `TenantsEndpoint` is unreachable, times out, returns an error other than `401`/`403`, or returns
unparseable JSON, AuthProxy responds with `503 Service Unavailable` instead of reporting that the
user has no organization. Document navigations and tenant-selection callbacks receive
`service-unavailable.html`; other callers receive a bare `503` without an HTML page.
An authoritative empty list or `401`/`403` response still proceeds to the normal no-tenant handling
(`no-organization.html` at `403` when no lobby is configured).

If the signed-in session no longer has a forwardable identity, AuthProxy signs the user out instead
of reporting a service outage. Navigations redirect to provider selection with `reason=invalid-session`;
other callers receive `401`.

A selected tenant that has not been confirmed within `Session.TenantRevalidationInterval` is not forwarded while `TenantsEndpoint` cannot answer: requests receive `503`, and anonymous, invitation and registration paths continue with no tenant. See [tenant selection](tenant-selection.md#when-the-endpoint-cannot-answer).

---

## Tenant registry

For `Host`, `Claim`, and `Route`, AuthProxy resolves a source identifier and then looks up the tenant ID in `Cratis:AuthProxy:Tenants`.

```json
{
  "Cratis": {
    "AuthProxy": {
      "Tenants": {
        "acme": {
          "Domains": ["acme.example.com"],
          "SourceIdentifiers": ["acme", "tenant-acme"]
        },
        "contoso": {
          "Domains": ["contoso.example.com"],
          "SourceIdentifiers": ["contoso", "tenant-contoso"]
        }
      }
    }
  }
}
```

---

## Lobby fallback

When no tenant can be resolved and the [lobby](lobby/index.md) is configured, AuthProxy redirects the user to the lobby frontend instead of returning `401 Unauthorized`.

If no lobby is configured and `TenantResolutions` is non-empty, AuthProxy returns `401 Unauthorized`.
When `TenantResolutions` is empty, the request proceeds without a tenant.

---

## Tenant verification

After tenant resolution, AuthProxy can verify that the tenant exists before forwarding the request.
This is optional.

### Global verification configuration

```json
{
  "Cratis": {
    "AuthProxy": {
      "TenantVerification": {
        "UrlTemplate": "https://platform.example.com/api/tenants/{tenantId}"
      }
    }
  }
}
```

| Property | Type | Description |
|----------|------|-------------|
| `UrlTemplate` | `string` | URL template for tenant verification. Use `{tenantId}` placeholder. |

### Response handling

- `200`: tenant exists, request proceeds.
- `404`: tenant does not exist; AuthProxy serves `tenant-not-found.html` with `404`.
- Any other status or network error: treated as tenant verification failure, and `tenant-not-found.html` is served.

If a strategy provides a strategy-specific verification URL template (for example `SubHost.Options.VerificationUrlTemplate`), that template is used instead of the global `TenantVerification.UrlTemplate`.

### Tenant not found page

When verification fails, AuthProxy serves `tenant-not-found.html`.
See [Error pages](error-pages.md) to override this page.

---

## Credential binding

A credential bound to tenant A cannot authorize a request addressing tenant B, even when the person belongs
to both tenants. AuthProxy compares tenant identifiers with `OrdinalIgnoreCase`: `Tenant-A` and `tenant-a`
name the same tenant. It does not trim or otherwise repair identifiers. This tenant mismatch refusal is always enabled, including
unsigned deployments and deployments without resource or environment scoping.

For browser sessions, the protected selected-tenant cookie and tenants resolved from `Claim` are credential
constraints. An on-behalf session uses only its represented tenant, not the actor's own claims or selection.
AuthProxy client-credentials tokens use their verified `cratis/tenant` claim; the same claim from another
authentication scheme does not create a client-credentials binding. `Host`, `SubHost`, `Route` and `Specified`
address the target tenant. `Default` supplies a fallback, not another credential constraint; when that fallback
wins resolution, the effective tenant is still checked against the credential before namespace selection or forwarding.
Tenant comparisons use `OrdinalIgnoreCase`, consistently with on-behalf tenancy checks. Resource and environment
comparisons remain ordinal and case-sensitive.

AuthProxy refuses an addressed mismatch with `403` and `Cache-Control: no-store` before membership lookup, tenant
verification, namespace selection or forwarding. Pending invitation and registration cookies do not bypass binding checks. Its warning identifies the credential kind and redacted
request path without logging tenant values. An unbound session can still use an addressed tenant, subject to
the usual membership checks. When Selection is configured, an authenticated browser addressing a tenant through
Host, SubHost or Route must confirm membership through the configured tenants endpoint, even without a selection
cookie or with a legacy plain cookie. Host and SubHost confirmation issues a host-only bound selection cookie.
Route confirmation does not bind the shared host to one tenant; it uses the per-account, per-tenant memory cache
and the normal revalidation interval instead. Each newly addressed tenant still requires membership confirmation. A pending invitation or registration cookie may defer selection,
but cannot authorize forwarding to an unconfirmed tenant. Deployments without Selection keep their existing
addressing behavior. Legacy unsigned selection cookies do not establish a binding; the tenant-selection
flow confirms them as before. Switch tenants through `/.cratis/select-tenant`, rather than replaying a selection
on another tenant's host. Invitation, registration, authentication-bootstrap and declared anonymous paths remain
reachable before tenant selection.

A browser session without a tenant binding remains unbound and uses normal tenant selection and membership
verification. A foreign resource/environment selection cookie is discarded. If the session is otherwise valid
and authenticated, AuthProxy reconfirms membership through the tenants endpoint and redirects to the original
path without forwarding that application request or using the foreign cookie's tenant. An encrypted session
ticket from another resource/environment cannot authenticate the caller and does not reach a backend.

To isolate AuthProxy-issued credentials by resource or environment, set `Cratis:AuthProxy:CredentialBinding:Resource`
and/or `Cratis:AuthProxy:CredentialBinding:Environment` to trusted deployment identifiers. Each defaults to an
empty string (no declared binding). A declared value accepts letters, digits, `-`, `.`, `_` and `~`, up to 256
characters, with no surrounding whitespace; invalid configuration prevents startup. Never derive these settings
from caller input. Enabling or changing them signs everyone out once; restart every replica with identical
settings. See [data-protection binding](data-protection.md#multi-replica-checklist).

## Bearer routes

On a [bearer route](services.md#bearer-routes) the tenant comes from the access token alone: the claim named by
`TenantClaimType` (`tid` by default). `Host`, `SubHost` and `Route` resolutions constrain the addressed target:
a token naming another tenant is refused with `403`. `Specified` and `Default` do not override or constrain the
token tenant on bearer routes. The tenant-selection cookie is never read and the tenant-selection page is never served.

A route can also set `EnvironmentClaimType`, for example `env`. This requires a declared
`CredentialBinding:Environment` at startup and exactly one non-empty claim value on each token, matching that
environment exactly. Missing or mismatched values produce `403`; case and whitespace variants are not repaired.
The route's `Audiences` continue to enforce the resource constraint through the token's `aud` claim.

- A token that does not carry exactly one tenant, or carries one that is not made of letters, digits, `-`, `.`,
  `_` or `~` (at most 256 characters), is refused with `403`. There is no fallback to a default tenant.
- When [tenant verification](#tenant-verification) is configured, the tenant is verified the same way; a tenant
  that fails verification is refused with `403` rather than the tenant-not-found page.
- The tenant is forwarded as `x-cratis-tenant-id`, with `Tenant-ID` as a deprecated copy. It records which tenant
  the user chose when the token was granted; the backend still decides whether the user is a member of it.
