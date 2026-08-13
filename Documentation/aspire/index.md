# Aspire Hosting Integration

## Canonical provider identity

Use the canonical provider helpers when every downstream identity path must use one explicitly selected
provider subject:

```csharp
authProxy.WithCanonicalOidcProvider(
    "Microsoft Entra",
    OidcProviderType.Microsoft,
    "https://login.microsoftonline.com/<tenant-id>/v2.0",
    clientId,
    clientSecret,
    "entra-workforce",
    "oid");
```

For OAuth providers, `WithCanonicalOAuthProvider` additionally requires the explicit issuer assigned to the
authenticated user-information flow. The existing `WithOidcProvider` and `WithOAuthProvider` helpers remain
unchanged and retain legacy identity behavior.

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

### Identity verification denials

After declaring a service's identity endpoint as an authorization authority, you can make any denial end
the caller's local AuthProxy session:

```csharp
authproxy
    .WithIdentityVerification("main", IdentityVerificationMode.Required)
    .WithSessionTerminationOnIdentityDenial();
```

`WithSessionTerminationOnIdentityDenial` is global and composes deterministically across services: calling
it more than once still writes the same enabled session setting. A denial clears AuthProxy's local session
before the existing `403` response; it does not initiate logout at the external identity provider. Omit the
call to preserve the default behavior, where the authenticated session remains active after a denial.

See [Identity verification](../configuration/services.md#identity-enrichment) for the denial matrix
and the direct configuration equivalent.

### Anonymous paths

Declare the request paths on a service that should be served without a session — a magic-link
landing page, a signed-token report, a public webhook receiver. Call `WithAnonymousPaths` once
per service; each call accumulates entries:

```csharp
authproxy.WithAnonymousPaths("main", "/welcome", "/api/webhooks/payments");
```

Each entry is a rooted path prefix, matched case-insensitively on segment boundaries — `/welcome`
covers `/welcome` and `/welcome/anything`, but not `/welcomex`. AuthProxy still strips inbound
identity headers on these paths and the application remains responsible for authorizing them.

See [Anonymous paths](../configuration/services.md#anonymous-paths) for the full matching rules
and what the flag does and does not change.

### Trusted proxies

Declare the peers directly in front of AuthProxy, so their `X-Forwarded-For` and `X-Forwarded-Proto`
are believed and everybody else's are not:

```csharp
authproxy
    .WithTrustedProxies("10.0.0.0/8", "203.0.113.7")
    .WithForwardLimit(2);
```

`WithTrustedProxies` takes IP addresses and CIDR ranges and accumulates across calls; an entry that
is neither is refused when the app host builds. `WithForwardLimit` is the number of hops a request
legitimately passes through, and it decides which address ends up reported as the client — see
[Trusted Proxies](../configuration/trusted-proxies.md) for how to choose it and what an untrusted
caller can do while it is unset.

---

## Admission

Close the interactive contract, so AuthProxy answers nothing at all until a caller presents a
capability the deployment's own verifier admits:

```csharp
authproxy.WithCapabilityOnlyAdmission("https://members.example.com/admit");
```

That is the whole minimum — the verifier URL has no default, because the verifier is your service and
inventing an address for it would mean a misconfigured deployment silently calling something else.
Everything else does:

```csharp
authproxy.WithCapabilityOnlyAdmission(
    verifierUrl: "https://members.example.com/admit",
    path: "/enter",                            // default "/.cratis/admission"
    maximumLength: 512,                        // default 4096 bytes
    entryLifetime: TimeSpan.FromMinutes(30));  // default 20 minutes
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `verifierUrl` | ✓ | Absolute `http`/`https` URL that decides whether a presented capability admits. |
| `path` | – | The one path a capability may be presented on. |
| `maximumLength` | – | The largest capability, in bytes, AuthProxy will read. |
| `entryLifetime` | – | How long an admitted browser stays admitted. |

Do not shorten `entryLifetime` below fifteen minutes: ASP.NET Core allows that long at the identity
provider, so a shorter entry expires while the handshake is still live and the caller comes back to a
`404` with nothing anywhere to diagnose it from.

It cannot be combined with `WithInvite` — AuthProxy refuses the combination at startup rather than
silently ordering two capability mechanisms. Without this call nothing changes: the default mode is
`Public`, which is how every release before it behaved.

See [Admission](../configuration/admission.md) for the verifier request/response contract, what an
operator should expect to observe, and the `/.cratis/token` caveat for machine clients.

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

For invitation acceptance, also configure the OAuth provider's `VerifiedEmailEndpoint` as
`https://api.github.com/user/emails` through AuthProxy configuration. The `user:email` scope shown above lets
AuthProxy establish exactly one primary verified address instead of trusting the nullable address on `/user`.

See [Authentication](../configuration/authentication.md) for the full configuration reference.

For an invite system that creates or links accounts, enable signed two-stage attestations after calling
`WithInvite`:

```csharp
authproxy.WithSignedInvitationAttestations(
    stageUrl: "https://lobby.example.com/_invite/stage",
    issuer: "https://auth.example.com",
    audience: "ada-lobby",
    keyId: "invite-2026-08",
    privateKeyPem: invitationSigningKey);
```

Load `invitationSigningKey` from a secret provider and configure the invitation authority with only the matching
public key. Signed attestations also require recipient binding — call
[`WithInviteEmailBinding`](#binding-an-invitation-to-the-invited-email) with a non-empty claim and pass a
`tenantClaim` to `WithInvite`, or AuthProxy fails options validation at startup. See
[Invitation to Organization](../configuration/lobby/invitation-to-organization.md) for the claims,
two calls, verification rules, and rotation sequence.

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

### Binding an invitation to the invited email

By default an invite is a bearer token: any subject who signs in holding it can redeem it. To bind it to the
address it was issued to, name the claim in the invite token that carries that address:

```csharp
authproxy.WithInviteEmailBinding("invited_email");
```

Compose this after either `WithInvite` overload. AuthProxy then compares that claim against the email evidence
the identity provider supplied for the signed-in session, before the second-stage exchange runs. When the
provider offers no usable address, the invite is rejected with `invitation-email-unavailable.html`; when the
address differs from the invited one — or the provider explicitly reports `email_verified=false` — with
`invitation-email-mismatch.html`.

Omitting the call, or passing an empty claim, writes nothing and retains the released default of no recipient
binding.

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

See [Lobby](../configuration/lobby/index.md) for the onboarding flow walkthroughs.
