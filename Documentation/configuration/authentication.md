# Authentication

AuthProxy supports three authentication modes that can be active simultaneously:

- **Interactive browser sessions** – OpenID Connect (OIDC) with a cookie.
- **Machine-to-machine / API** – JWT Bearer tokens from an external identity provider.
- **Back-channel client credentials** – service-owned client credentials verified by the target service itself.

---

## OIDC providers

Configure one or more OpenID Connect providers under `Cratis:AuthProxy:Authentication:OidcProviders`.

**Single provider** – the auth proxy challenges unauthenticated browser requests directly with that provider:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Authentication": {
        "OidcProviders": [
          {
            "Name": "Microsoft",
            "Type": "Microsoft",
            "Authority": "https://login.microsoftonline.com/<tenant-id>/v2.0",
            "ClientId": "<client-id>",
            "ClientSecret": "<client-secret>"
          }
        ]
      }
    }
  }
}
```

**Multiple providers** – the auth proxy redirects unauthenticated browser requests to a built-in
provider-selection page (`/.cratis/select-provider`) so the user can choose which provider to log in with:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Authentication": {
        "OidcProviders": [
          {
            "Name": "Microsoft",
            "Type": "Microsoft",
            "Authority": "https://login.microsoftonline.com/<tenant-id>/v2.0",
            "ClientId": "<client-id>",
            "ClientSecret": "<client-secret>",
            "Scopes": []
          },
          {
            "Name": "Google",
            "Type": "Google",
            "Authority": "https://accounts.google.com",
            "ClientId": "<client-id>",
            "ClientSecret": "<client-secret>",
            "Scopes": []
          }
        ]
      }
    }
  }
}
```

Each provider generates a dedicated login endpoint at `/.cratis/login/{scheme}`.
The scheme name is derived from the provider `Name` by lowercasing and replacing spaces with hyphens
(e.g. `"My Provider"` → `/.cratis/login/my-provider`).

Both behaviors above — the direct challenge and the selection page — apply to **browser navigations**.
A caller that is not navigating to a page is refused with `401` instead, so the rejection is visible to
a client that checks the status code. See [Unauthenticated responses](unauthenticated-responses.md).

### Tenant-aware authentication state

When authentication starts from a tenant-scoped request, AuthProxy stores tenant resolution metadata in the protected authentication `state` value:

- Tenant ID
- Tenant resolution strategy
- Strategy-specific metadata (for `SubHost`, the configured `ParentHost`)

On callback (`/signin-{scheme}`), AuthProxy reads this state and re-applies strategy behavior before finishing sign-in. For `SubHost`, AuthProxy reconstructs the tenant URL and redirects back to that tenant host.

Example flow:

1. Request arrives at `https://some-tenant.cratis.studio/`
2. AuthProxy resolves tenant `some-tenant` via `SubHost`
3. Challenge is sent with protected state containing tenant metadata
4. Provider redirects back to `https://auth.cratis.studio/signin-github?...&state=...`
5. AuthProxy restores tenant metadata from state
6. AuthProxy redirects to `https://some-tenant.cratis.studio/` (original return URL preserved)

This allows a common callback endpoint while still restoring tenant-specific behavior after sign-in.

### OidcProviderConfig properties

| Property | Type | Description |
|----------|------|-------------|
| `Name` | `string` | Display name shown on the login selection page. |
| `Type` | `string` | Provider type hint (`Microsoft`, `Google`, or `Custom`). |
| `Authority` | `string` | OIDC authority URL. |
| `ClientId` | `string` | OAuth 2.0 client ID. |
| `ClientSecret` | `string` | OAuth 2.0 client secret. |
| `Scopes` | `string[]` | Additional scopes to request (beyond `openid`, `profile`, `email`). |
| `ResponseMode` | `string` | How the provider returns the authorization code: `Query` (default) or `FormPost`. See below. |

#### Response mode and the handshake cookies

The handshake only completes when the provider callback carries the correlation cookie, and that cookie is
`SameSite=Lax` — which a browser attaches to a top-level GET and withholds from a cross-site POST. The
default `Query` response mode therefore has the provider return the authorization code in a top-level GET
redirect, and the handshake cookies stay `Lax`.

Some providers mandate a form POST callback — Apple whenever the `name` or `email` scopes are requested.
Setting `ResponseMode` to `FormPost` opts that provider into it, which also switches that provider's
correlation and nonce cookies to `SameSite=None; Secure` — a cross-site POST only ever carries `None`
cookies, and `None` requires HTTPS. Do not choose `FormPost` for providers that support `Query`; it trades
away the `Lax` hardening for nothing.

### Canonical federated identity

Provider registrations can opt into a stable, provider-aware account tuple. Without this section,
AuthProxy preserves its legacy claim-selection and payload behavior, except that the reserved
`urn:cratis:identity:*` namespace is always removed from fresh legacy callbacks before session storage.

```json
{
  "Cratis": {
    "AuthProxy": {
      "Authentication": {
        "OidcProviders": [
          {
            "Name": "Microsoft Entra",
            "Type": "Microsoft",
            "Authority": "https://login.microsoftonline.com/<tenant-id>/v2.0",
            "ClientId": "<client-id>",
            "ClientSecret": "<client-secret>",
            "CanonicalIdentity": {
              "ProviderKey": "entra-workforce",
              "SubjectClaimType": "oid"
            }
          }
        ]
      }
    }
  }
}
```

| Property | Applies to | Contract |
|----------|------------|----------|
| `InvitationCompletionEnabled` | OIDC and OAuth | Opts this provider into signed invitation completion. Defaults to `false`; ordinary sign-in remains available. Enable only when the provider can produce the exact verified email evidence below. |
| `InvitationIdentityBindingCompletionEnabled` | OIDC and OAuth | Opts this provider into signed invitations already bound by the invitation issuer to an immutable provider subject. Defaults to `false`. This mode does not infer email ownership; enable it only for a tenant-scoped immutable subject and framework-validated issuer. |
| `ProviderKey` | OIDC and OAuth | Stable lowercase ASCII key, independent of display name and authentication scheme. Keys must be unique across configured providers. |
| `SubjectClaimType` | OIDC and OAuth | Exact claim type on the resulting authenticated `ClaimsPrincipal` that supplies the subject. Exactly one nonempty value is required, and the claim type must be outside the entire case-insensitive `urn:cratis:identity:*` namespace reserved for AuthProxy-authored metadata. There is no fallback to `sub`, name, username, or email. For OAuth user-info fields, map the raw JSON field to this principal claim with `ClaimMappings`. |
| `EmailClaimType` | OIDC and OAuth | Exact provider-derived claim used for a signed invitation attestation. Defaults to `email`; exactly one address-shaped value is required during invitation completion. |
| `EmailVerifiedClaimType` | OIDC and OAuth | Exact provider-derived boolean claim proving ownership of `EmailClaimType`. Defaults to `email_verified`; only one value equal to `true` is accepted. |
| `AssuranceClaimType` | OIDC and OAuth | Exact provider-derived assurance claim. Defaults to `acr`; it must be present exactly once for invitation completion. |
| `Issuer` | OAuth only | Explicit absolute HTTPS issuer assigned to the authenticated user-info flow. OIDC providers must omit it because AuthProxy uses the issuer from the framework-validated OIDC token. |

An identity-bound invitation carries both `recipient_provider_key` and `recipient_identity_binding` in the signed
invitation capability. AuthProxy accepts only one exact 43-character base64url SHA-256 binding, restricts provider
selection to the exact canonical provider key, and completes only through a provider explicitly opted into
`InvitationIdentityBindingCompletionEnabled`. AuthProxy treats the binding as opaque: the invitation authority must
independently recompute and compare it from the attested provider key, validated issuer, and immutable subject.
For Microsoft Entra, use a tenant-specific authority and `SubjectClaimType=oid`; never substitute email,
`preferred_username`, or the mutable display name for the object identifier.

For OAuth, `SubjectClaimType` names the claim after the configured user-info claim actions have run, not
the raw JSON property returned by the provider. This complete example maps the raw user-info `id` field to
a principal `sub` claim and then selects that `sub` claim as the canonical subject:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Authentication": {
        "OAuthProviders": [
          {
            "Name": "GitHub Enterprise",
            "Type": "GitHub",
            "AuthorizationEndpoint": "https://github.example.com/login/oauth/authorize",
            "TokenEndpoint": "https://github.example.com/login/oauth/access_token",
            "UserInformationEndpoint": "https://github.example.com/api/user",
            "VerifiedEmailEndpoint": "https://github.example.com/api/user/emails",
            "ClientId": "<client-id>",
            "ClientSecret": "<client-secret>",
            "Scopes": ["read:user", "user:email"],
            "ClaimMappings": {
              "sub": "id"
            },
            "CanonicalIdentity": {
              "ProviderKey": "github-workforce",
              "SubjectClaimType": "sub",
              "Issuer": "https://github.example.com"
            }
          }
        ]
      }
    }
  }
}
```

Given a user-info response such as `{ "id": 12345, "login": "octocat" }`, the mapping produces the
principal claim `sub=12345`; canonical resolution reads that resulting `sub` claim. Without the mapping,
setting `SubjectClaimType` to `sub` fails closed because no such principal claim exists.

For OAuth providers such as GitHub whose ordinary user-information response can omit private addresses, configure
`VerifiedEmailEndpoint`. AuthProxy calls it with the provider access token and accepts exactly one JSON-array entry
whose `primary` and `verified` properties are both `true` and whose `email` property is nonempty. It replaces any
ordinary user-information email with that verified value and writes the configured email-verification claim as
`true`. A malformed, ambiguous, missing, or non-success response establishes no invitation email evidence. Request
the provider scope needed by that endpoint (`user:email` for GitHub).

When a provider supplies no configured assurance claim, AuthProxy records the successfully completed protocol as
`oidc` or `oauth` in `AssuranceClaimType`. A provider-supplied value such as OIDC `acr` takes precedence. These values
describe authentication assurance only; they do not grant application roles or membership.

AuthProxy normalizes issuer scheme and host casing, removes a default port and trailing slash, and rejects
userinfo, query strings, and fragments. Plain HTTP is accepted only for a loopback development issuer.
The stable account key is the complete `(providerKey, normalizedIssuer, subject)` tuple. A raw subject is
not globally unique: two providers can issue the same value, and some providers issue pairwise or
client-specific subjects that change when the client registration changes.

For Microsoft Entra workforce accounts, configure `SubjectClaimType` as `oid` when the tenant object ID is
the intended account identifier. Do not use `preferred_username`, `upn`, or email as a subject. Those values
are mutable and can be reassigned. For a provider where `sub` is the intended client-specific identifier,
configure `sub` explicitly.

After a fresh provider callback, AuthProxy removes case-insensitive collisions with its reserved claims and
adds exactly one AuthProxy-authored set:

- `urn:cratis:identity:provider-key`
- `urn:cratis:identity:issuer`
- `urn:cratis:identity:subject`

The canonical subject also becomes `ClientPrincipal.UserId` and therefore the
`x-ms-client-principal-id` value. Provider and issuer travel in the base64 client principal's claim list;
downstream Arc applications receive those claims even though Arc does not preserve the client principal's
`identityProvider` JSON property. The same tuple is posted by invitation exchange, credential linking, and
sign-in notification.

`x-ms-client-principal-id` is therefore the provider's raw subject value, not a globally unique account key.
Do not key cross-provider data or authorization by that header alone. Consumers that need the stable account
identity must use all three reserved canonical claims as the `(providerKey, normalizedIssuer, subject)` tuple.

#### Canonical session continuity

A successful canonical browser sign-in binds the authentication cookie to the static provider registration
that issued it. AuthProxy writes an opaque, versioned registration fingerprint into the protected
authentication ticket for a normal sign-in callback. A credential-link callback does not create or replace a
session, so it does not write this fingerprint.

AuthProxy recalculates the fingerprint whenever it validates the cookie. The user must authenticate again if
any of these registration inputs changed:

- Provider protocol (`OIDC` or `OAuth`) or derived authentication scheme
- Canonical `ProviderKey` or `SubjectClaimType`
- Configured client ID or the effective client ID on the named authentication handler
- For OIDC, `Authority` or the effective `MetadataAddress`
- For OAuth, the normalized configured canonical `Issuer`; both the configured provider value and the
  effective named-handler value for `AuthorizationEndpoint`, `TokenEndpoint`, and `UserInformationEndpoint`;
  and every configured `ClaimMappings` key/value pair. Mapping order does not affect the fingerprint.

The fingerprint contains no subject, email, claims, tokens, client secret, or other PII or secret input. It is
an internal continuity marker, not an account identifier and not a claim forwarded to downstream services.

OIDC issuers are different from static registration. AuthProxy records the issuer from the framework-validated
token in each canonical session, but does not include that runtime issuer in the registration fingerprint. An
unchanged multi-tenant OIDC registration can therefore accept sessions whose validated issuers differ by tenant.
For OAuth, there is no validated ID-token issuer: the explicit canonical `Issuer` is static configuration, is
checked again during cookie validation, and changing it forces reauthentication.

The backward-compatibility carve-out applies only to a true legacy cookie: it has neither a claim in the
case-insensitive `urn:cratis:identity:*` namespace nor a canonical registration fingerprint, and its recorded
authentication scheme does not currently resolve to a canonical provider. AuthProxy accepts that cookie without
applying canonical continuity. If a marker-free cookie's recorded scheme now resolves to a canonical provider,
AuthProxy rejects it and signs out the cookie session so the user establishes the canonical tuple through a fresh
provider callback. A cookie that carries either canonical marker is likewise rejected and signed out when its
canonical tuple or fingerprint is missing, malformed, or mismatched.

Canonical identity proves provider authentication metadata only. Applications still decide membership,
roles, scopes, and authorization. AuthProxy identity headers are authenticated by deployment topology, not
by a per-request signature: prevent clients from reaching downstream services directly. Before forwarding any
request, AuthProxy removes all inbound `x-ms-client-principal`, `x-ms-client-principal-id`, and
`x-ms-client-principal-name` values. It writes exact trusted replacements only when it has an authenticated
principal, so an unauthenticated caller cannot smuggle identity headers downstream.

---

## OAuth 2.0 providers

Not every provider publishes an OpenID Connect discovery document. GitHub is the common one that does not,
so it is configured under `Cratis:AuthProxy:Authentication:OAuthProviders` with its endpoints named
explicitly instead of discovered from an authority:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Authentication": {
        "OAuthProviders": [
          {
            "Name": "GitHub",
            "Type": "GitHub",
            "AuthorizationEndpoint": "https://github.com/login/oauth/authorize",
            "TokenEndpoint": "https://github.com/login/oauth/access_token",
            "UserInformationEndpoint": "https://api.github.com/user",
            "ClientId": "<client-id>",
            "ClientSecret": "<client-secret>",
            "Scopes": [ "read:user", "user:email" ],
            "ClaimMappings": {
              "sub": "id",
              "name": "name",
              "preferred_username": "login",
              "email": "email"
            }
          }
        ]
      }
    }
  }
}
```

OAuth providers sit alongside OIDC providers in every other respect: they appear on the
provider-selection page, they get a login endpoint at `/.cratis/login/{scheme}`, and the count of both
together decides whether an unauthenticated browser is challenged directly or offered a choice.

`ClaimMappings` is what turns the provider's user-info JSON into claims — the key is the claim type to
create, the value is the field to read it from. The mapping above produces the claims AuthProxy reads when
it builds the forwarded principal.

> [!NOTE]
> OAuth 2.0 has no standard end-session endpoint, so signing out of an OAuth-established session clears
> the local session only — the user stays signed in at the provider. See [Logout](logout.md).

### OAuthProviderConfig properties

| Property | Type | Description |
|----------|------|-------------|
| `Name` | `string` | Display name shown on the login selection page, and the source of the scheme name. |
| `Type` | `string` | Provider brand (`GitHub`, `Microsoft`, `Google`, `Apple`, or `Custom`). Picks the logo, and for GitHub also enables [organization and team claims](authorization.md#github-organizations-and-teams). |
| `AuthorizationEndpoint` | `string` | The OAuth 2.0 authorization endpoint URL. |
| `TokenEndpoint` | `string` | The OAuth 2.0 token endpoint URL. |
| `UserInformationEndpoint` | `string` | The user-information (profile) API endpoint URL. |
| `ClientId` | `string` | OAuth 2.0 client ID. |
| `ClientSecret` | `string` | OAuth 2.0 client secret. |
| `Scopes` | `string[]` | Scopes to request. Adding `read:org` to a GitHub provider also adds organization and team claims to the session. |
| `ClaimMappings` | `object` | Claim type → user-info JSON field name. |

Configuring a provider decides *who can sign in*, which on a public provider is everybody. To decide who
may then get through, see [Authorization](authorization.md).

---

## Session lifetime and re-validation

Interactive browser sessions are cookie-based, and every cookie AuthProxy issues for identity or tenant
context is **session-scoped or short-lived** — closing the browser ends them. On top of that,
`Cratis:AuthProxy:Session` bounds what a browser session that never closes may keep:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Session": {
        "Lifetime": "12:00:00",
        "SlidingExpiration": false,
        "IdentityRevalidationInterval": "00:10:00",
        "TenantRevalidationInterval": "00:10:00"
      }
    }
  }
}
```

| Property | Default | Description |
|----------|---------|-------------|
| `Lifetime` | `12:00:00` | Absolute lifetime of the authentication ticket. When it elapses the user must re-authenticate with the identity provider, even in a browser session that never closed. |
| `SlidingExpiration` | `false` | Whether activity extends the ticket lifetime. Disabled by default so `Lifetime` is a hard bound. |
| `IdentityRevalidationInterval` | `00:10:00` | How long a resolved authorization is remembered before the identity details — and the authorization they represent — are re-resolved against the services. Zero or negative falls back to ten minutes. |
| `TenantRevalidationInterval` | `00:10:00` | How long a tenant selected through the [tenant-selection flow](tenant-selection.md) is trusted before it is re-validated against `TenantsEndpoint`, so revoked tenant access takes effect without per-request backend calls. Zero or negative disables re-validation. |

The authentication cookie itself carries no persistent `Expires` — the browser drops it when the session
ends — and is `HttpOnly`, `SameSite=Lax`, and marked `Secure` whenever the site is served over HTTPS.
Re-validation is cached in memory per instance, so within an interval no extra backend calls are made;
when the interval lapses, a single backend round-trip refreshes the cached identity or tenant context.

### The two identity cookies

The resolved identity is written to two cookies, and the split is a security boundary rather than an
implementation detail:

| Cookie | Readable by script | Contents | Role |
|--------|--------------------|----------|------|
| `.cratis-identity` | Yes | Base64 JSON identity details | Lets a frontend render the signed-in user without a round-trip. **Never** treated by AuthProxy as evidence of anything. |
| `.cratis-identity-authorization` | No (`HttpOnly`) | A sealed, unforgeable record | Carries the authorization decision that is allowed to skip the `/.cratis/me` call on later requests. |

Because `.cratis-identity` is deliberately script-readable, anything a client can write must not decide
authorization — so the decision lives in the sealed cookie instead. It is protected with ASP.NET data
protection and bound to the user and tenant it was issued for, and its expiry is carried *inside* the
sealed value rather than left to the cookie's `Max-Age`, which a non-browser client is free to ignore. A
record that cannot be unsealed (for example after a data-protection key rotation) is not a failure: the
caller is simply re-authorized against the services.

AuthProxy still reads unexpired version-one authorization records issued for legacy identities. That legacy
format separated the expiry, raw subject, and tenant with `|`, so compatibility is limited to presented legacy
subjects and tenant IDs that do not contain that delimiter. A delimiter-bearing value is rejected and the caller
is re-authorized. Current version-two records use structured fields and do not inherit this legacy restriction.

Deployments running more than one AuthProxy instance should configure a shared
`DataProtectionKeysPath` so a record sealed by one instance can be read by the others; without it each
instance re-resolves identity for callers whose record it did not issue.

---

## Forwarded identity headers

Once a request is authenticated, AuthProxy tells the backend who is calling. It does that with four
headers, written on every proxied request and on every `/.cratis/me` call — and it strips any inbound copy
first, so a backend can treat them as proof rather than as a claim.

| Header | Carries | Encoding |
|--------|---------|----------|
| `x-ms-client-principal` | The full client principal as base64-encoded JSON | Always base64, so always US-ASCII |
| `x-ms-client-principal-id` | The provider-local subject | Verbatim, or RFC 8187 — no sibling announces which |
| `x-ms-client-principal-name` | The display name (`userDetails`) | Verbatim, or RFC 8187 when it cannot travel verbatim |
| `x-ms-client-principal-name*` | The RFC 8187 form of the display name | Present **exactly** when the plain header carries an encoded value |
| `Tenant-ID` | The resolved tenant | Verbatim, or RFC 8187 — no sibling announces which |

### Every header value is US-ASCII

A display name is whatever the identity provider says it is, and providers say things like
`Søren Wærstad`, `Ольга Иванова`, `田中太郎`. An HTTP header field is octets, and .NET refuses to write a
character above `U+007F` to one — it throws before a byte reaches the socket. So a name outside US-ASCII
did not arrive garbled at the backend; the proxied request failed at the gateway and the identity-endpoint
call failed silently, and the person could not use the application at all.

AuthProxy now guarantees that every value it writes is printable US-ASCII. A value that already is one —
and that could not be mistaken for an encoded one, see below — is sent **byte for byte unchanged**, so if
your users' names are ASCII nothing about the wire format changes and no extra header appears. Anything
else is sent as an [RFC 8187](https://www.rfc-editor.org/rfc/rfc8187) `ext-value`: percent-encoded UTF-8
behind a self-describing `UTF-8''` prefix.

```http
x-ms-client-principal-name: UTF-8''S%C3%B8ren%20W%C3%A6rstad
x-ms-client-principal-name*: UTF-8''S%C3%B8ren%20W%C3%A6rstad
```

The starred sibling is the same idiom `Content-Disposition` uses to pair `filename` with `filename*`
(RFC 6266 §4.3). Its **presence is the signal**: when `x-ms-client-principal-name*` is there, the plain
header carries an encoded value; when it is absent, the plain header is the name verbatim. The plain
header is always populated either way, so a backend that gates on the three headers being present keeps
working untouched.

Because the encoder emits only RFC 8187 `attr-char` octets, an encoded value can never contain `CR`, `LF`
or `NUL`. That alone is not the whole guarantee, though, because a consumer that *decodes* can reconstruct
whatever the encoding hid. A name a person chose to write as `UTF-8''victim%0D%0AX-Admin:%20true` is
printable US-ASCII from end to end, so it would travel verbatim — and a backend that decided to decode
because the value *looked* encoded would get a carriage return, a line feed and a header of the caller's
choosing back out of it.

So the rule is not "encode what ASCII cannot carry", it is **encode anything that could be mistaken for an
encoded value**. A value beginning with `UTF-8''` is itself encoded, however ordinary the rest of it is,
and the sibling header is emitted for it. Decoding it returns the literal name the person typed. The
guarantee that follows is precise:

> Decode exactly the values the sibling header announces, exactly once, and no identity value can put `CR`,
> `LF` or `NUL` into a header on your side.

No realistic display name begins with `UTF-8''`, so nothing about ordinary traffic changes.

> [!IMPORTANT]
> The sibling header exists only for `x-ms-client-principal-name`. `x-ms-client-principal-id` and
> `Tenant-ID` go through the same encoder — a value outside US-ASCII on either is sent as an `ext-value` —
> but nothing announces it, so for those two headers the `UTF-8''` prefix is the only signal there is. That
> is deliberate: a subject and a tenant identifier are values your identity provider and your configuration
> issue, not values a person types, so treat them as opaque and forward them rather than decoding them. If
> you do decode one, decode it once and treat the result as data, never as a header.

### `x-ms-client-principal` is the canonical value

The base64 principal is the source of truth for identity. Its `userDetails` property is the exact
original name — every code point, no encoding, no normalization — because base64 was never subject to the
ASCII limit in the first place.

Read `userDetails` when you need the name itself. Read `x-ms-client-principal-name` when you want a
convenient header and can either accept the encoded form or decode it. Cratis Arc already takes the first
route: its Microsoft Identity Platform handler builds the user from the base64 principal, so an
Arc backend behind AuthProxy sees exact Unicode names with no changes on its side.

```csharp
// Decoding the header form yourself, when you are not on Arc.
// Gate on the sibling header, never on the prefix: the sibling is what AuthProxy states, and the
// prefix is only what the value looks like. A name a person typed as "UTF-8''..." looks encoded
// and is not, and decoding it because it looked encoded is how a display name becomes a header.
var name = request.Headers["x-ms-client-principal-name"].ToString();
if (request.Headers.ContainsKey("x-ms-client-principal-name*"))
{
    name = Uri.UnescapeDataString(name["UTF-8''".Length..]);
}
```

Decode once, and once only. The result is the person's name, and a name is data — put it in a model, a
log field or a response body, never back into a header.

---

## JWT Bearer (API)

For machine-to-machine calls, configure a JWT Bearer handler:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Authentication": {
        "JwtBearer": {
          "Authority": "https://login.microsoftonline.com/<tenant-id>/v2.0",
          "Audience": "<api-audience>"
        }
      }
    }
  }
}
```

---

## Back-channel client credentials

AuthProxy can also issue bearer tokens itself after a proxied service verifies the supplied
client credentials over a private back channel.

1. The client sends `POST /.cratis/token`
2. The request body uses standard OAuth form fields:
   - `grant_type=client_credentials`
   - `service=<service-key>` (optional when only one service has client credentials configured)
   - `client_id=<client-id>`
   - `client_secret=<client-secret>`
3. AuthProxy calls the configured downstream verification endpoint with a JSON payload:

```json
{
  "service": "portal",
  "routePrefix": "/api",
  "clientId": "orders-api",
  "clientSecret": "<client-secret>"
}
```

4. Any `2xx` response mints a bearer token scoped to that service and route prefix
5. Any `4xx` response rejects the credentials
6. Any `5xx` response is treated as a downstream verification failure

Successful responses from `/.cratis/token` look like this:

```json
{
  "access_token": "<authproxy-issued-token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<authproxy-issued-refresh-token>"
}
```

The issued bearer token can then be used on the configured route prefix (for example `/api/**`).
AuthProxy validates that the token is used against the same configured service and route before
forwarding the request.

### Resolving a tenant from the verification response

The `2xx` response from the verification endpoint may optionally include a JSON body with a `tenant` property:

```json
{
  "tenant": "acme"
}
```

When present, AuthProxy embeds that value in the minted access token (and any refresh token issued
alongside it) as a `cratis/tenant` claim. The claim travels with the token for its entire lifetime, so
every subsequent request authenticated with that token carries it.

To have AuthProxy resolve the tenant and set the `Tenant-ID` header on proxied requests, add a `Claim`
[tenant resolution strategy](tenancy.md#claim-strategy-options) pointing at that claim type:

```json
{
  "Cratis": {
    "AuthProxy": {
      "TenantResolutions": [
        { "Strategy": "Claim", "Options": { "ClaimType": "cratis/tenant" } }
      ]
    }
  }
}
```

Like every other `Claim`-resolved value, the tenant returned by the verification endpoint is matched
against the `SourceIdentifiers` configured for each entry in `Cratis:AuthProxy:Tenants` — it is not
used directly as the Cratis tenant ID unless a tenant also lists it as one of its own source identifiers.
See [Tenant registry](tenancy.md#tenant-registry) for how that mapping works.

### Refreshing a token

A client can exchange a refresh token for a new access token without resupplying its client
credentials:

1. The client sends `POST /.cratis/token`
2. The request body uses:
   - `grant_type=refresh_token`
   - `refresh_token=<refresh-token>`
3. AuthProxy validates the refresh token and, if it is still valid, mints a new access token
   and a new refresh token for the same service, client, and tenant — the response shape is
   identical to the one shown above.

Refresh tokens are valid for 30 days and are not re-verified against the downstream service on
refresh — since the client secret is not resent, AuthProxy trusts the refresh token itself rather
than calling back to the target service. There is no revocation list: a leaked refresh token
remains usable until it naturally expires, so treat it as a credential and keep its exposure to the
same standard as a client secret.

An expired or unrecognized refresh token is rejected with `401 Unauthorized` and
`error: "invalid_grant"`. Refresh tokens cannot be used as access tokens (and vice versa) — each is
protected separately, so presenting one where the other is expected is always rejected.

### Data Protection keys and horizontal scaling

The authentication cookie and AuthProxy-issued client-credentials access and refresh tokens are all
encrypted using ASP.NET Core Data Protection. By default, keys are not shared across instances. Running
more than one AuthProxy replica, or needing sessions and client-credentials tokens to survive a restart,
requires mounting a persistent, shared volume and pointing `Cratis:AuthProxy:DataProtectionKeysPath`
at it:

```json
{
  "Cratis": {
    "AuthProxy": {
      "DataProtectionKeysPath": "/mnt/dataprotection-keys"
    }
  }
}
```

Without this, a client-credentials token minted by one replica will fail to validate on another,
and all outstanding tokens and sessions are invalidated on every restart.
