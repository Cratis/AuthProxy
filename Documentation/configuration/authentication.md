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
  "expires_in": 3600
}
```

The issued bearer token can then be used on the configured route prefix (for example `/api/**`).
AuthProxy validates that the token is used against the same configured service and route before
forwarding the request.
