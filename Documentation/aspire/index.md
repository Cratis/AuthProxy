# Aspire Hosting Integration

The `Cratis.AuthProxy.Aspire` NuGet package adds first-class .NET Aspire support for AuthProxy.
Instead of configuring environment variables by hand, you wire up authentication, tenancy, and
service routing with a concise fluent API in your `AppHost`.

## Installation

```bash
dotnet add package Cratis.AuthProxy.Aspire
```

## Adding AuthProxy as a container resource

This is the typical path for external consumers who run AuthProxy from Docker Hub:

```csharp
var authproxy = builder.AddAuthProxy("authproxy", tag: "latest")
    .WithHttpEndpoint(port: 8080)
    .WithBackend("main", apiResource)
    .WithFrontend("main", webResource)
    .WithOidcProvider(
        "Microsoft",
        OidcProviderType.Microsoft,
        authority: "https://login.microsoftonline.com/<tenant-id>/v2.0",
        clientId: "<client-id>",
        clientSecret: "<client-secret>")
    .WithHostTenantResolution();
```

`AddAuthProxy` creates an `AuthProxyResource` backed by the `cratis/authproxy` Docker Hub image.
Pin `tag` to a specific release in production environments — the default `"latest"` is convenient
for local development.

## Adding AuthProxy as a project resource

When working inside the AuthProxy repository itself (or in a monorepo that includes AuthProxy
source), use `AddProject` with the same extension methods:

```csharp
var authproxy = builder.AddProject<Projects.AuthProxy>("authproxy")
    .WithBackend("main", apiResource)
    .WithFrontend("main", webResource);
```

All `With*` methods work on any `IResourceBuilder<T> where T : IResourceWithEnvironment`,
so you can mix container and project resources freely.

---

## Services

Use `WithBackend` and `WithFrontend` to register the resources that AuthProxy should proxy:

```csharp
authproxy
    .WithBackend("main", apiResource)
    .WithFrontend("main", webResource);
```

Both methods accept an optional `endpointName` parameter (defaults to `"http"`) that selects
which endpoint from the target resource to forward to.

### Identity details resolution

For each service with a backend, AuthProxy calls `GET {baseUrl}/.cratis/me` after authentication
to enrich the identity cookie.  This behaviour is on by default.  To disable it for a specific
service, pass `resolveIdentityDetails: false` to `WithBackend`:

```csharp
authproxy
    .WithBackend("reporting", reportingApi, resolveIdentityDetails: false)
    .WithFrontend("reporting", reportingWeb);
```

See [Services](../configuration/services.md) for the underlying configuration model.

---

## Authentication

### OIDC providers

```csharp
authproxy.WithOidcProvider(
    name: "Contoso AD",
    type: OidcProviderType.Microsoft,
    authority: "https://login.microsoftonline.com/<tenant-id>/v2.0",
    clientId: "<client-id>",
    clientSecret: "<client-secret>",
    scopes: ["api://my-api/.default"]);
```

Call `WithOidcProvider` once per provider. Multiple calls produce a provider-selection page.

The `OidcProviderType` enum contains well-known provider brands:

| Value | Description |
|-------|-------------|
| `Custom` | Generic / unknown provider. |
| `Microsoft` | Microsoft Identity Platform (Azure AD / Entra ID). |
| `Google` | Google Identity. |
| `GitHub` | GitHub OAuth / OIDC. |
| `Apple` | Apple Sign-In. |

### OAuth 2.0 (non-OIDC) providers

For providers that do not expose an OIDC discovery document, use `WithOAuthProvider`:

```csharp
authproxy.WithOAuthProvider(
    name: "GitHub",
    type: OidcProviderType.GitHub,
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    tokenEndpoint: "https://github.com/login/oauth/access_token",
    userInformationEndpoint: "https://api.github.com/user",
    clientId: "<client-id>",
    clientSecret: "<client-secret>",
    scopes: ["user:email"],
    claimMappings: new Dictionary<string, string>
    {
        ["sub"] = "id",
        ["name"] = "login",
        ["email"] = "email"
    });
```

See [Authentication](../configuration/authentication.md) for the full configuration reference.

---

## Tenant resolution

Add one or more resolution strategies. They run in order until a tenant is matched:

| Method | Strategy |
|--------|----------|
| `WithHostTenantResolution()` | Matches the request host against configured tenant domains. |
| `WithSubHostTenantResolution()` | Derives the tenant from the first subdomain (e.g. `acme.example.com` → `acme`). |
| `WithClaimTenantResolution(claimType?)` | Reads a claim from the authenticated user. |
| `WithRouteTenantResolution(pattern)` | Extracts a source identifier from the request path by regex. |
| `WithSpecifiedTenantResolution(tenantId)` | Pins all requests to one fixed tenant (single-tenant deployments). |
| `WithDefaultTenantResolution(tenantId)` | Fallback when no other strategy resolves a tenant. |
| `WithSelectionTenantResolution()` | Reads the tenant from the cookie set by the tenant-selection page. |

```csharp
authproxy
    .WithSubHostTenantResolution()
    .WithDefaultTenantResolution("lobby");
```

See [Tenancy](../configuration/tenancy.md) for detailed strategy documentation.

### Tenant verification

After resolution, AuthProxy can confirm the tenant exists by calling your back-end.  You can
pass a raw URL template or reference an Aspire service resource directly:

```csharp
// Raw URL template
authproxy.WithTenantVerification("https://platform.example.com/api/tenants/{tenantId}");

// Aspire resource reference — endpoint is resolved automatically
authproxy.WithTenantVerification(platformApi, "/api/tenants/{tenantId}");
```

AuthProxy issues a `GET` to the resolved URL. A `200` response lets the request proceed; `404` or
any error serves the `tenant-not-found.html` page.

---

## Tenant selection

When users can be members of more than one tenant, the `Selection` strategy presents a
tenant-selection page after login.  You can pass a raw URL or reference an Aspire service resource:

```csharp
// Raw URL
authproxy.WithSelectionTenantResolution(
    tenantsEndpoint: "https://platform.example.com/api/tenants/selectable");

// Aspire resource reference — endpoint is resolved automatically
authproxy.WithSelectionTenantResolution(platformApi, "/api/tenants/selectable");
```

AuthProxy calls the endpoint after login and, if more than one tenant is returned, serves the
built-in `select-tenant.html` page.  If only one tenant is returned the selection page is
skipped and the user is redirected immediately.

The endpoint must return a JSON array of `{ "id": "...", "name": "..." }` objects.

See [Tenant Selection Page](../configuration/tenant-selection.md) for details on building a
custom selection page and the full flow.

---

## Invites, registration and lobby

### Core invite configuration

Configure the invite system with the RSA public key and exchange endpoint.  You can pass a raw URL
or reference an Aspire service resource for the exchange endpoint:

```csharp
// Raw URL
authproxy.WithInvite(
    publicKeyPem: File.ReadAllText("invite-public-key.pem"),
    exchangeUrl: "https://studio.example.com/internal/invites/exchange",
    issuer: "https://studio.example.com",
    audience: "authproxy",
    tenantClaim: "tenant_id",
    subjectAlreadyExistsUrl: "https://app.example.com/errors/account-already-exists");

// Aspire resource reference — exchange endpoint URL is resolved automatically
authproxy.WithInvite(
    publicKeyPem: File.ReadAllText("invite-public-key.pem"),
    exchangeServiceResource: studioApi,
    exchangeRoute: "/internal/invites/exchange",
    issuer: "https://studio.example.com",
    tenantClaim: "tenant_id");
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `publicKeyPem` | ✓ | PEM-encoded RSA public key to verify invite token signatures. |
| `exchangeUrl` | ✓ | Endpoint called after login to exchange the invite token. |
| `issuer` | – | Expected `iss` claim. Omit to skip issuer validation. |
| `audience` | – | Expected `aud` claim. Omit to skip audience validation. |
| `tenantClaim` | – | Claim that carries the tenant ID for tenant-issued invite detection. |
| `subjectAlreadyExistsUrl` | – | Redirect URL when the exchange endpoint returns HTTP 409. Omit to serve the built-in page. |

### Claim forwarding

To propagate invite-token claims into the principal sent to `/.cratis/me` endpoints, call
`WithInviteClaimForwarding` once per claim:

```csharp
authproxy
    .WithInviteClaimForwarding("organization_id", toClaimType: "organization")
    .WithInviteClaimForwarding("invited_by");
```

When `toClaimType` is omitted the original claim type is preserved.

### Lobby

The lobby is the service users are redirected to when no tenant can be resolved — typically
an onboarding application.  At minimum, configure the lobby frontend:

```csharp
authproxy
    .WithLobbyFrontend(lobbyResource)
    .WithLobbyBackend(lobbyApiResource);   // optional
```

`WithLobbyFrontend` and `WithLobbyBackend` both accept an optional `endpointName` parameter
(defaults to `"http"`).

### Registration

To send users through the AuthProxy registration bootstrap flow, configure a lobby registration URL:

```csharp
authproxy.WithLobbyRegistration(lobbyResource, "/register");

// or use a raw URL
authproxy.WithLobbyRegistration("https://lobby.example.com/register");
```

This sets `Cratis:AuthProxy:Invite:Lobby:Registration:BaseUrl`. Users who visit `/register`
authenticate through AuthProxy and are then redirected to that registration URL.

See [Invites, Registration & Lobby](../configuration/invites.md) for the full onboarding flow walkthrough.
