---
title: "Identity Token Exchange"
description: "Exchange allow-listed external issuer tokens for tenant-bound Identity access tokens on opted-in bearer routes."
---

# Identity token exchange

Token exchange is **off by default**. A bearer route can opt in to exchange allow-listed external tokens
through [Cratis Identity's token-exchange endpoint](https://github.com/Cratis/Identity/blob/main/Documentation/token-exchange.md).
Identity owns external-token verification, account linking, tenant membership and grant decisions. AuthProxy
sends the subject token only to the configured endpoint; it never treats the external token as a local credential.

Configure this example as a service's `BearerRoutes` entry, alongside an independently configured Host,
SubHost or Route tenant resolver:

```json
{
  "PathPrefix": "/mcp",
  "TenantClaimType": "tenant_id",
  "Issuers": [{ "Issuer": "https://identity.example" }],
  "Audiences": ["direct-mcp"],
  "RequiredScopes": ["direct-mcp:read"],
  "TokenExchange": {
    "Endpoint": "https://identity.example/connect/token",
    "ClientId": "authproxy-direct",
    "Resource": "https://cratis.direct/mcp",
    "Audience": "direct-mcp",
    "Scopes": ["direct-mcp:read"],
    "ResultIssuer": "https://identity.example",
    "Issuers": [{ "Issuer": "https://external.example", "SubjectTokenType": "jwt" }]
  }
}
```

Supply `TokenExchange.ClientSecret` through your secret store or an environment variable such as
`Cratis__AuthProxy__Services__direct__BearerRoutes__0__TokenExchange__ClientSecret`. Do not put secrets in
checked-in configuration. Register this confidential client and its allowed scopes, tenants and resources in Identity.

`Resource` and `Audience` are separate trusted operator settings. `Resource` is the RFC 8707 resource indicator
sent to Identity; `Audience` is the catalog audience expected in the returned JWT. Copy both from
[Identity's resource catalogue contract](https://github.com/Cratis/Identity/blob/main/Documentation/specs/identity-contract-v1.md).
For example, `https://cratis.direct/mcp` maps to `direct-mcp`, not to the URI itself. AuthProxy accepts an absolute
HTTPS URI or URN as resource syntax; use an indicator actually admitted by your Identity catalogue.
`Audience` must equal an entry in the route's `Audiences`. Neither value, nor scopes or endpoint, comes from caller input.

The external `Issuers` list is exact and separate from the route's local `Issuers`; overlap, duplicates,
relative issuers and a self-exchange configuration fail startup. `SubjectTokenType` is `jwt` (default) or
`access_token`, translated to the corresponding RFC 8693 URN. Unknown issuers are not exchanged and must
pass the unchanged local JWT validator. Direct Identity tokens bypass exchange.

Before contacting Identity, AuthProxy resolves every configured Host, SubHost and Route target, requires them
to agree exactly (including case), and verifies that the tenant exists. The subject token's tenant claims,
caller headers, browser selection, defaults and specified/claim resolvers cannot select the exchange tenant.
No target, conflicting targets or a nonexistent tenant returns 403 without calling Identity.

Only the exchanged token goes through the normal signature, issuer, audience, lifetime, scope, DPoP and
activity checks. It must have the configured `ResultIssuer`, an `aud` containing `Audience`, the exact requested
`tenant_id`, and an `idp` equal to the original external issuer. A tenant or idp mismatch after successful validation
returns 403. Missing, repeated or unusable tenant claims and invalid tokens return 401. External subject or idp
values are not copied into the validated result. Existing policy and forwarding rules still apply.

The HTTPS endpoint cannot contain credentials, query or fragment and is never followed through a redirect.
Malformed responses, redirects, non-Bearer results, refresh tokens and lifetimes outside 1–300 seconds return
401. Identity throttling, transport failure, timeout or temporary unavailability also returns 401 with `no-store`,
never a login redirect or fallback to the raw token. A bounded integer `Retry-After` may be forwarded.
`offline_access` and combining `TokenExchange` with `Dpop` fail startup validation.

`Timeout` defaults to three seconds (100 milliseconds–10 seconds allowed). `MaximumCachedTokens` defaults
to 10,000 (1–1,000,000 allowed). Concurrent identical exchanges share one request. Successful results are
cached by a SHA-256 key covering the subject token, exact tenant, issuer, resource, scopes and configuration,
only until the shorter of `expires_in` and JWT `exp`. Failures are not cached and failed validation evicts a result.
[Online activity checks](authentication.md#revocation-edge-introspection) remain independent; exchange is not a revocation check.
