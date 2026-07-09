# Services

AuthProxy routes requests to one or more **services** using [YARP](https://microsoft.github.io/reverse-proxy/).
Each service may expose a **backend** (API), a **frontend** (SPA / static assets), or both.

---

## Configuration

Services are configured under `Cratis:AuthProxy:Services`, keyed by a friendly name:

```json
{
  "Cratis": {
    "Services": {
      "portal": {
        "Backend": { "BaseUrl": "http://portal-api:8080/" },
        "Frontend": { "BaseUrl": "http://portal-web:3000/" },
        "ResolveIdentityDetails": true,
        "ClientCredentials": {
          "RoutePrefix": "/api",
          "VerificationPath": "/.cratis/client-credentials/verify"
        }
      },
      "catalog": {
        "Backend": { "BaseUrl": "http://catalog-api:8080/" }
      }
    }
  }
}
```

### ServiceConfig properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Backend` | `ServiceEndpointConfig` | `null` | API backend endpoint. |
| `Frontend` | `ServiceEndpointConfig` | `null` | SPA / static-asset frontend endpoint. |
| `ResolveIdentityDetails` | `bool?` | `true` when Backend is set | Whether to call `/.cratis/me` on this service to enrich the identity cookie. |
| `ClientCredentials` | `ServiceClientCredentialsConfig` | `null` | Enables back-channel client-credentials verification and token minting for this service. |

### ServiceEndpointConfig properties

| Property | Type | Description |
|----------|------|-------------|
| `BaseUrl` | `string` | Base URL of the endpoint (e.g. `http://my-service:8080/`). |

### ServiceClientCredentialsConfig properties

| Property | Type | Description |
|----------|------|-------------|
| `RoutePrefix` | `string` | Route prefix that AuthProxy-issued bearer tokens are allowed to access (for example `/api`). |
| `VerificationPath` | `string` | Internal verification endpoint. Relative values are resolved against `Backend.BaseUrl`; absolute values are used as-is. |

---

## Routing

### Single service

When only one service is configured, AuthProxy adds a plain catch-all route so the service
is reachable without any special routing header or query parameter.

- `/{**path}` → frontend
- `/api/{**path}` → backend

### Multiple services

With more than one service, clients must indicate the target using one of:

| Mechanism | Example |
|-----------|---------|
| `Service-ID` request header | `Service-ID: portal` |
| `service` query parameter | `?service=portal` |

Routes are matched case-insensitively.

---

## Identity enrichment

For each service with a `Backend` endpoint (and `ResolveIdentityDetails` not explicitly set to
`false`), AuthProxy calls `GET {Backend.BaseUrl}/.cratis/me` after authentication.
The response is stored in a short-lived HTTP-only cookie (`.cratis-identity`) and injected as
the `X-MS-CLIENT-PRINCIPAL` header on every proxied request so that backend services can read
identity details without re-calling the identity endpoint themselves.

---

## Client credentials

When `ClientCredentials` is configured for a service, AuthProxy exposes `POST /.cratis/token`.
That endpoint forwards the supplied client credentials to the service's verification endpoint and,
on success, issues a bearer token scoped to the configured `RoutePrefix`.

This creates a one-to-one relationship between:

- the proxied service
- the route prefix the token may access
- the downstream endpoint that verifies the client credentials
