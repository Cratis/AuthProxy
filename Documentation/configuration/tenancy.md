# Tenancy

Ingress resolves a **tenant ID** (GUID) from every incoming request and stores it in the request
context. Downstream services receive the resolved tenant ID via the `X-Tenant-ID` header.

---

## Tenant resolution strategies

Resolution strategies are evaluated **in order** until one succeeds.
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
```

### Available strategies

| Strategy | Description |
|----------|-------------|
| `Host` | Extracts the hostname from the `Host` header and looks it up in `Cratis:AuthProxy:Tenants`. |
| `Claim` | Reads a claim value from the authenticated user's `ClaimsPrincipal`. |
| `Route` | Matches a regex pattern against the request path to extract a tenant identifier. |
| `Specified` | Uses a fixed, statically configured tenant ID for all requests. |

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

If `ClaimType` is omitted, the strategy falls back to reading the `X-MS-CLIENT-PRINCIPAL` header
(Azure App Service format).

---

## Route strategy options

```json
{
  "Strategy": "Route",
  "Options": {
    "Pattern": "^/tenant/(?<tenant>[^/]+)"
  }
}
```

The named group `tenant` is used as the tenant identifier, which is then matched against
`Cratis:AuthProxy:Tenants`.

---

## Specified strategy options

```json
{
  "Strategy": "Specified",
  "Options": {
    "TenantId": "00000000-0000-0000-0000-000000000001"
  }
}
```

---

## Tenant registry

Each strategy (except `Specified`) resolves a **source identifier** string that is matched
against the `Cratis:AuthProxy:Tenants` dictionary to obtain the final tenant GUID.

```json
{
  "Cratis": {
    "AuthProxy": {
    "Tenants": {
      "00000000-0000-0000-0000-000000000001": {
        "SourceIdentifiers": [ "myapp.example.com" ]
      },
      "00000000-0000-0000-0000-000000000002": {
        "SourceIdentifiers": [ "otherapp.example.com" ]
      }
    }
  }
}
```

---

## Lobby fallback

When no tenant can be resolved and the [invite lobby](invites.md) is configured, the user is
redirected to the lobby frontend instead of receiving a `401 Unauthorized` response.
See [Invites & Lobby](invites.md) for details.

If no lobby is configured and `TenantResolutions` is non-empty, Ingress returns `401 Unauthorized`.
When `TenantResolutions` is empty (not configured), the request proceeds without a tenant.

---

## Tenant verification

After a tenant has been resolved Ingress can verify that it actually **exists** in your platform
before forwarding the request. This is an opt-in feature — when not configured all resolved
tenants are accepted without a remote check.

### How it works

Ingress issues an HTTP GET to a configurable URL. The remote service must return:

- **200** – tenant exists, request proceeds.
- **404** – tenant does not exist; Ingress serves `tenant-not-found.html` with HTTP 404.
- Any other status or network error – Ingress treats the tenant as not found and serves the same page.

### Configuration

```json
{
  "Cratis": {
    "AuthProxy": {
    "TenantVerification": {
      "UrlTemplate": "https://platform.example.com/api/tenants/{tenantId}"
    }
  }
}
```

| Property | Type | Description |
|----------|------|-------------|
| `UrlTemplate` | `string` | URL to call for verification. Use `{tenantId}` as a placeholder for the resolved tenant GUID. |

The `{tenantId}` placeholder is replaced at runtime with the resolved tenant ID.

### Tenant not found page

When verification fails, the `tenant-not-found.html` page is served.
See [Error pages](error-pages.md) for how to override this page with your own custom version.
