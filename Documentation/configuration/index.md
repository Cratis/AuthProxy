# Configuration

Cratis AuthProxy is configured entirely through the `Cratis:AuthProxy` section of `appsettings.json`
(or equivalent environment variables using the `Cratis__AuthProxy__` prefix).

```json
{
  "Cratis": {
    "AuthProxy": {
      "Authentication": { ... },
      "Authorization": { ... },
      "Admission": { ... },
      "TenantResolutions": [ ... ],
      "TenantVerification": { ... },
      "Tenants": { ... },
      "Services": { ... },
      "Ingress": { ... },
      "Invite": { ... },
      "Management": { ... },
      "PagesPath": "",
      "DataProtectionKeysPath": ""
    }
  }
}
```

| Topic | Description |
|-------|-------------|
| [Authentication](authentication.md) | OIDC providers, OAuth 2.0 providers such as GitHub, and JWT Bearer configuration. |
| [Authorization](authorization.md) | Requiring a claim — a role, a group, a GitHub organization or team — before any request is forwarded. |
| [Admission](admission.md) | Answering nothing at all until a caller presents a capability your own verifier admits, for a deployment whose existence is not meant to be discoverable. |
| [Tenancy](tenancy.md) | How the auth proxy resolves the current tenant from each request, and how to verify tenant existence. |
| [Tenant Selection Page](tenant-selection.md) | How selection-based tenant resolution works and how to build/override `select-tenant.html`. |
| [Trusted Proxies](trusted-proxies.md) | Which callers may speak for the client through `X-Forwarded-For` and `X-Forwarded-Proto`, and how many hops to follow. |
| [Services](services.md) | Routing requests to backend and frontend services. |
| [Management Listener](management-listener.md) | An opt-in private listener carrying liveness and readiness endpoints, so a probe tests more than "a process accepted a socket". |
| [Lobby](lobby/index.md) | Invite and registration flows that hand users off to the lobby experience. |
| [Well-Known Pages](well-known-pages.md) | Built-in HTML pages (provider selection, errors, tenant not found) and how to override them via a mounted volume. |
