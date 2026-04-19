# Tenancy

AuthProxy resolves a **tenant ID** string from each incoming request and stores it in the request context.
Downstream services receive the resolved tenant ID via the `Tenant-ID` header.

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

If `ClaimType` is omitted, AuthProxy falls back to reading `X-MS-CLIENT-PRINCIPAL`.

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

When no tenant can be resolved and the [invite lobby](invites.md) is configured, AuthProxy redirects the user to the lobby frontend instead of returning `401 Unauthorized`.

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
