---
title: "Configuration"
description: "Configure AuthProxy through the Cratis:AuthProxy section of appsettings.json or Cratis__AuthProxy__ environment variables, with an overview of the settings."
---

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
      "Session": { ... },
      "SignIn": { ... },
      "OnBehalf": { ... },
      "Logout": { ... },
      "Ingress": { ... },
      "Invite": { ... },
      "Link": { ... },
      "Management": { ... },
      "GrpcListener": { ... },
      "BackendTls": { ... },
      "Profile": "Default",
      "Dpop": { ... },
      "CredentialBinding": { ... },
      "SearchIndexing": { ... },
      "ActivityTimeout": "00:05:00",
      "PagesPath": "",
      "DataProtectionKeysPath": "",
      "DataProtection": { ... }
    }
  }
}
```

| Topic | Description |
|-------|-------------|
| [Authentication](authentication.md) | OIDC providers, OAuth 2.0 providers such as GitHub, JWT Bearer configuration, and bearer routes for access tokens from an external authorization server. |
| [Application Configuration Contract](application-contract.md) | Starting AuthProxy from a Screenplay model's provider list and a Cratis environment's values, including secrets from mounted files and the application's Ante. |
| [Authorization](authorization.md) | Requiring a claim — a role, a group, a GitHub organization or team — before any request is forwarded. |
| [Admission](admission.md) | Answering nothing at all until a caller presents a capability your own verifier admits, for a deployment whose existence is not meant to be discoverable. |
| [On-behalf Sessions](on-behalf-sessions.md) | Letting a support person or agent act on behalf of one user in one tenant, for one issue, while the application confirms a live grant. |
| [Tenancy](tenancy.md) | How the auth proxy resolves the current tenant from each request, and how to verify tenant existence. |
| [Credential Binding](tenancy.md#credential-binding) | Binding AuthProxy-issued credentials to a trusted resource and environment through `CredentialBinding`. |
| [Tenant Selection Page](tenant-selection.md) | How selection-based tenant resolution works and how to build/override `select-tenant.html`. |
| [Data Protection Keys](data-protection.md) | Sharing the key ring that encrypts sessions and tokens between replicas: a file system, Azure Blob Storage or Redis, with optional Azure Key Vault key protection. |
| [Trusted Proxies](trusted-proxies.md) | Which callers may speak for the client through `X-Forwarded-For` and `X-Forwarded-Proto`, and how many hops to follow. |
| [DPoP Proof Verification](dpop.md) | Opt-in OAuth-only route proof verification with trusted public origins, nonces and a fleet-shared Redis replay store. |
| [Backend TLS](backend-tls.md) | Client certificates, private CA trust and required HTTPS for backend connections (`BackendTls`), and the deployment `Profile` (`Default`, or `LocalDevelopment` on developer machines only). |
| [Services](services.md) | Routing requests to backend and frontend services, and the idle timeout that applies to proxied requests, WebSockets and SSE streams. |
| [gRPC Services](grpc-services.md) | Forwarding gRPC calls to a gRPC backend, including the opt-in HTTP/2-only `GrpcListener` behind an ingress that terminates TLS. |
| [One Proxy, Several Hosts](one-proxy-several-hosts.md) | Giving each application its own host behind one AuthProxy and one sign-in, with a shared session cookie and a single identity-provider callback. |
| [Telemetry](telemetry.md) | OpenTelemetry traces and metrics, exported only when an OTLP endpoint is configured. |
| [Management Listener](management-listener.md) | An opt-in private listener carrying liveness and readiness endpoints, so a probe tests more than "a process accepted a socket". |
| [Credential Linking](link.md) | Letting a signed-in user link another identity-provider login to their account (`Link`). |
| [Search-Index Exclusion](search-indexing.md) | Asking search engines to keep AuthProxy hosts out of their indexes (`SearchIndexing`). |
| [Lobby](lobby/index.md) | Invite and registration flows that hand users off to the lobby experience. |
| [Well-Known Pages](well-known-pages.md) | Built-in HTML pages (provider selection, errors, tenant not found) and how to override them via a mounted volume. |

## Refusing public paths before routing

To keep an internal endpoint off the public host, configure `Ingress:DeniedPathPrefixes`:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Ingress": {
        "DeniedPathPrefixes": [ "/internal/" ]
      }
    }
  }
}
```

The equivalent environment variable is `Cratis__AuthProxy__Ingress__DeniedPathPrefixes__0=/internal/`.
The list defaults to empty; when empty, it does not inspect or refuse any paths. Invalid entries fail
startup: each prefix must start with `/` and contain only plain ASCII, without `%`, `\`, `..`,
whitespace, controls, `;`, `?` or `#`. `/` refuses every request, including probes and sign-in callbacks.

When enabled, the guard answers with an empty 404 before routing, authentication, anonymous-path
handling, tenant resolution, static assets, management answers or gRPC/YARP forwarding. It matches
case-insensitively on segment boundaries: `/internal`, `/INTERNAL/x` and `/internal//x` are refused,
but `/internalx` and `/api/internal/x` are not. It decodes once, merges repeated slashes and resolves
`.` and `..` segments before comparing. Query strings do not participate in the comparison.

The guard reads `IHttpRequestFeature.RawTarget`, not `Request.Path`: Kestrel has already decoded and
may have normalized the latter. The raw target preserves encoded separators and the original path on
the public host, before any `PathBase` split or service-prefix stripping. For example, if the public
path is `/shared/internal`, configure `/shared/internal`, not `/internal`. There is no
`RequireSharedPrefixSupport` setting in AuthProxy; service `PathPrefix`/`StripPathPrefix` rewriting
happens later. An embedding host must call `UseDeniedPathPrefixes()` before its own request handlers.
An external ingress that rewrites paths before AuthProxy must enforce the original public boundary
itself, or preserve the public path when forwarding.

With any prefix configured, ambiguous paths also get 404, even outside the listed prefixes: encoded
slashes or backslashes, literal backslashes, malformed escapes, invalid UTF-8, controls, whitespace,
`;` path parameters, literal or decoded `#`, decoded `?`, any residual `%` after decoding (including
double encoding), or `..` above the root. Only origin-form raw targets starting with `/` are accepted;
missing targets, absolute-form targets and unescaped non-ASCII bytes are refused rather than guessed.
Well-formed percent-encoded UTF-8 is accepted. Refusal logs are Debug-level and contain no path or query.
