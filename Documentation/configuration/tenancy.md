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
| `ParentHost` | `string` | Parent host suffix used to extract the tenant ID from request host. |
| `VerificationUrlTemplate` | `string` | Optional strategy-specific verification URL template. Overrides global `TenantVerification.UrlTemplate` for this strategy. |

`SubHost` resolves directly to the subhost tenant ID and does not require a `Tenants` dictionary lookup.
Use `VerificationUrlTemplate` to validate that the resolved tenant exists before forwarding requests.

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
