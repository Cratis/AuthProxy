# Invites & Lobby

Ingress includes a two-phase invite flow that lets you onboard new users via signed JWT invite
tokens, and an optional **lobby** microservice to which users without a resolved tenant are
redirected while they complete the onboarding process.

---

## How it works

### Phase 1 – Invite link

1. A user receives a link in the form `https://your-ingress/invite/<token>`.
2. Ingress validates the token against the configured RSA public key.
3. If the token is **valid**, it is stored in a short-lived HTTP-only cookie and the user is
   redirected to the OIDC login.
4. If the token has **expired** (valid signature but past its `exp` claim), Ingress serves
   `invitation-expired.html` with HTTP 401.
5. If the token is **invalid** (malformed, bad signature, or unparseable), Ingress serves
   `invitation-invalid.html` with HTTP 401.

### Phase 2 – Post-login exchange

1. After a successful OIDC login the user is redirected back.
2. Ingress detects the invite cookie, calls the configured `ExchangeUrl` with the token and the
   authenticated user's subject, then deletes the cookie.
3. If the exchange succeeds and a **lobby** microservice is configured, the user is redirected to
   the lobby's frontend so they can enter the application with their newly assigned tenant.

### Lobby – no-tenant redirect

Tenancy is resolved **before** the invite system.  
When Ingress cannot resolve a tenant for a request it checks whether a lobby is configured:

- **Lobby configured** – the user is redirected to the lobby's frontend URL, unless the request
  is already an invite path (`/invite/...`) or the user already holds a pending invite cookie (so
  that the Phase 2 exchange can complete).
- **No lobby** – Ingress returns `401 Unauthorized` when `TenantResolutions` is non-empty,
  or proceeds without a tenant when no resolutions are configured.

---

## Configuration

All invite and lobby settings live under `Ingress:Invite`:

```json
{
  "Ingress": {
    "Invite": {
      "PublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
      "Issuer": "https://studio.example.com",
      "Audience": "ingress",
      "ExchangeUrl": "https://studio.example.com/internal/invites/exchange",
      "Lobby": {
        "Frontend": { "BaseUrl": "http://lobby-service:3000/" },
        "Backend":  { "BaseUrl": "http://lobby-service:8080/" }
      }
    }
  }
}
```

### InviteConfig properties

| Property | Type | Description |
|----------|------|-------------|
| `PublicKeyPem` | `string` | PEM-encoded RSA public key used to verify invite token signatures. |
| `Issuer` | `string` | Expected `iss` claim. Leave empty to skip issuer validation. |
| `Audience` | `string` | Expected `aud` claim. Leave empty to skip audience validation. |
| `ExchangeUrl` | `string` | Absolute URL of the invite-exchange endpoint, e.g. `https://studio.example.com/internal/invites/exchange`. |
| `Lobby` | `MicroserviceConfig` | Optional lobby microservice. See below. |

### Lobby microservice

The `Lobby` property accepts a standard [`MicroserviceConfig`](microservices.md) object.
Only the `Frontend.BaseUrl` is required for the lobby redirect; a `Backend` endpoint is optional
and can be used if the lobby needs an API.

| Property | Type | Description |
|----------|------|-------------|
| `Frontend.BaseUrl` | `string` | URL to which users without a tenant (or after invite exchange) are redirected. |
| `Backend.BaseUrl` | `string` | Optional backend API URL for the lobby service. |

---

## Invite token format

Invite tokens are standard JWTs signed with an RSA private key held by the issuing service
(e.g. Cratis Studio).  The ingress only needs the matching **public key** to validate signatures.

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

Ingress distinguishes between two token failure modes and serves a dedicated page for each:

| Page file | Condition |
|-----------|-----------|
| `invitation-expired.html` | The token had a valid signature but has passed its `exp` claim. |
| `invitation-invalid.html` | The token is malformed, carries an invalid signature, or cannot be parsed. |

Both pages are served with HTTP 401.
These pages use full descriptive names rather than numeric error codes because they represent
application-level conditions, not generic HTTP errors.

See [Error pages](error-pages.md) for how to override these pages with your own custom versions.
