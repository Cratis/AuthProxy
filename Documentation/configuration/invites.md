# Invites & Lobby

AuthProxy includes a two-phase invite flow that lets you onboard new users via signed JWT invite
tokens, and an optional **lobby** service to which users without a resolved tenant are
redirected while they complete the onboarding process.

---

## How it works

### Phase 1 – Invite link

1. A user receives a link in the form `https://your-authproxy/invite/<token>`.
2. AuthProxy validates the token against the configured RSA public key.
3. If the token is **valid**, it is stored in a short-lived HTTP-only cookie.
   - If **only one** identity provider is configured, the user is redirected directly to that provider's login.
  - If **multiple** identity providers are configured, AuthProxy serves `invitation-select-provider.html`
     with a `.cratis-providers` cookie so the user can choose which provider to log in with.
4. If the token has **expired** (valid signature but past its `exp` claim), AuthProxy serves
   `invitation-expired.html` with HTTP 401.
5. If the token is **invalid** (malformed, bad signature, or unparseable), AuthProxy serves
   `invitation-invalid.html` with HTTP 401.

### Phase 2 – Post-login exchange

1. After a successful OIDC login the user is redirected back.
2. AuthProxy detects the invite cookie, calls the configured `ExchangeUrl` with the token and the
   authenticated user's subject, then deletes the cookie.
3. If the exchange endpoint returns **HTTP 409 Conflict** (subject already registered), AuthProxy
   redirects to `SubjectAlreadyExistsUrl` (if configured) or serves the built-in
   `invitation-subject-already-exists.html` page.
4. If the exchange succeeds and a **lobby** service is configured, the user is redirected to
   the lobby's frontend so they can enter the application with their newly assigned tenant.

### Lobby – no-tenant redirect

Tenancy is resolved **before** the invite system.  
When AuthProxy cannot resolve a tenant for a request it checks whether a lobby is configured:

- **Lobby configured** – the user is redirected to the lobby's frontend URL, unless the request
  is already an invite path (`/invite/...`) or the user already holds a pending invite cookie (so
  that the Phase 2 exchange can complete).
- **No lobby** – AuthProxy returns `401 Unauthorized` when `TenantResolutions` is non-empty,
  or proceeds without a tenant when no resolutions are configured.

---

## Configuration

All invite and lobby settings live under `Cratis:AuthProxy:Invite`:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Invite": {
        "PublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
        "Issuer": "https://studio.example.com",
        "Audience": "authproxy",
        "ExchangeUrl": "https://studio.example.com/internal/invites/exchange",
        "TenantClaim": "tenant_id",
        "SubjectAlreadyExistsUrl": "https://app.example.com/errors/account-already-exists",
        "AppendInvitationIdToQueryString": true,
        "InvitationIdQueryStringKey": "invitationId",
        "ClaimsToForward": [
          { "FromClaimType": "organization_id", "ToClaimType": "organization" },
          { "FromClaimType": "invited_by" }
        ],
        "Lobby": {
          "Frontend": { "BaseUrl": "http://lobby-service:3000/" },
          "Backend":  { "BaseUrl": "http://lobby-service:8080/" }
        }
      }
    }
  }
}
```

### Invite properties

| Property | Type | Description |
|----------|------|-------------|
| `PublicKeyPem` | `string` | PEM-encoded RSA public key used to verify invite token signatures. |
| `Issuer` | `string` | Expected `iss` claim. Leave empty to skip issuer validation. |
| `Audience` | `string` | Expected `aud` claim. Leave empty to skip audience validation. |
| `ExchangeUrl` | `string` | Absolute URL of the invite-exchange endpoint, e.g. `https://studio.example.com/internal/invites/exchange`. |
| `TenantClaim` | `string` | Claim in the invite token that contains the tenant ID string for tenant-issued invite detection. |
| `SubjectAlreadyExistsUrl` | `string` | URL to redirect to when the exchange endpoint returns HTTP 409 (subject already registered). Leave empty to serve the built-in `invitation-subject-already-exists.html` page. |
| `AppendInvitationIdToQueryString` | `bool` | Appends `jti` from the invite token to the lobby redirect query string when enabled. |
| `InvitationIdQueryStringKey` | `string` | Query string key used when appending invitation ID. |
| `ClaimsToForward` | `InviteClaimForwarding[]` | Claim mappings forwarded from invite token into the principal sent to identity details providers. |
| `Lobby` | `Service` | Optional lobby service. See below. |

### Invite claim forwarding

When `ClaimsToForward` is configured and a pending invite token cookie exists, AuthProxy reads the configured
invite-token claims and adds them to the principal payload sent to each `/.cratis/me` identity details endpoint.

- Existing identity-provider claims are preserved.
- Mapped invite claims are appended if present.
- If `ToClaimType` is empty, the original `FromClaimType` is used.

This gives you a decoupled extension point for propagating invitation context into identity resolution.

### InviteClaimForwarding properties

| Property | Type | Description |
|----------|------|-------------|
| `FromClaimType` | `string` | Claim type to read from the invite token payload. |
| `ToClaimType` | `string` | Claim type to emit in the principal sent to identity details providers. Defaults to `FromClaimType` when empty. |

### Lobby service

The `Lobby` property accepts a standard [`Service`](services.md) object.
Only the `Frontend.BaseUrl` is required for the lobby redirect; a `Backend` endpoint is optional
and can be used if the lobby needs an API.

| Property | Type | Description |
|----------|------|-------------|
| `Frontend.BaseUrl` | `string` | URL to which users without a tenant (or after invite exchange) are redirected. |
| `Backend.BaseUrl` | `string` | Optional backend API URL for the lobby service. |

---

## Invite token format

Invite tokens are standard JWTs signed with an RSA private key held by the issuing service
(e.g. Cratis Studio).  The auth proxy only needs the matching **public key** to validate signatures.

Recommended claims:

| Claim | Description |
|-------|-------------|
| `iss` | Issuer – must match `Invite.Issuer` if set. |
| `aud` | Audience – must match `Invite.Audience` if set. |
| `exp` | Expiry – tokens with a past `exp` are rejected. |
| `sub` | Subject – the invited user's identifier (passed to the exchange endpoint). |

---

## Well-known paths

| Path | Description |
|------|-------------|
| `/invite/<token>` | Phase 1 – validates the token and starts the OIDC flow. |

---

## Invitation error pages

AuthProxy distinguishes between two token failure modes and serves a dedicated page for each:

| Page file | Condition |
|-----------|-----------|
| `invitation-expired.html` | The token had a valid signature but has passed its `exp` claim. |
| `invitation-invalid.html` | The token is malformed, carries an invalid signature, or cannot be parsed. |
| `invitation-select-provider.html` | The token is valid and multiple identity providers are configured. |
| `invitation-subject-already-exists.html` | The authenticated user's subject is already associated with an existing account (exchange returned HTTP 409). |

All error pages are served with the following HTTP status codes:

| Page | HTTP status |
|------|-------------|
| `invitation-expired.html` | 401 |
| `invitation-invalid.html` | 401 |
| `invitation-select-provider.html` | 200 |
| `invitation-subject-already-exists.html` | 409 |
These pages use full descriptive names rather than numeric error codes because they represent
application-level conditions, not generic HTTP errors.

See [Error pages](error-pages.md) for how to override these pages with your own custom versions
and for details on the `.cratis-providers` cookie injected into the provider-selection page.

For a full walkthrough of creating a branded custom provider-selection page, including the cookie
format, JavaScript reading pattern, asset deployment, and a complete end-to-end flow diagram, see
[Custom Invitation Provider-Selection Page](invitation-provider-selection.md).
