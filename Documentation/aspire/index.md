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

After resolution, AuthProxy can confirm the tenant exists by calling your back-end:

```csharp
authproxy.WithTenantVerification("https://platform.example.com/api/tenants/{tenantId}");
```

AuthProxy issues a `GET` to the resolved URL. A `200` response lets the request proceed; `404` or
any error serves the `tenant-not-found.html` page.
