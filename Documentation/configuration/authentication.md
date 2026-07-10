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
