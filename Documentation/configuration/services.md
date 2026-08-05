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
        "AnonymousPaths": [ "/welcome", "/api/webhooks/payments" ],
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
| `AnonymousPaths` | `string[]` | `[]` | Path prefixes on this service served to unauthenticated callers. See [Anonymous paths](#anonymous-paths). |
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

## Anonymous paths

By default every path behind AuthProxy requires a session. An unauthenticated request is answered by
the provider-selection page if it is a browser navigation, or [refused with a status
code](unauthenticated-responses.md) if it is not — and anything that does reach the reverse proxy is
refused by the default authorization policy.

`AnonymousPaths` declares the paths a service genuinely serves without a session: a magic-link landing
page, a signed-token report, a public webhook receiver.

A declared path is reachable by anyone who knows the URL — AuthProxy stops demanding a login, it does not
authenticate the caller. The application remains responsible for deciding whether to trust the request.
For inbound webhooks specifically, see [Receiving webhooks](webhooks.md).

```json
{
  "Cratis": {
    "AuthProxy": {
      "Services": {
        "portal": {
          "Frontend": { "BaseUrl": "http://portal-web:3000/" },
          "Backend": { "BaseUrl": "http://portal-api:8080/" },
          "AnonymousPaths": [ "/welcome", "/api/webhooks/payments" ]
        }
      }
    }
  }
}
```

From Aspire:

```csharp
authProxy.WithAnonymousPaths("portal", "/welcome", "/api/webhooks/payments");
```

### Matching

Each entry is a **path prefix**, matched case-insensitively on segment boundaries — the same semantics
as the built-in invite, registration and authentication-UI paths.

| Declared | Matches | Does not match |
|----------|---------|----------------|
| `/welcome` | `/welcome`, `/welcome/`, `/WELCOME`, `/welcome/abc/def` | `/welcomex`, `/app/welcome` |
| `/api/webhooks/payments` | `/api/webhooks/payments/...` | `/api/webhooks`, `/api/webhooks/invoices` |

Because an entry covers everything below it, name the specific leaf path whenever a sibling under the
same parent is not public.

### What a valid entry looks like

An entry must be a rooted path whose segments are made only of the characters `A–Z`, `a–z`, `0–9`, `-`,
`.`, `_` and `~`. Anything else is **refused**, leaving that path authenticated.

Refusing rather than interpreting is deliberate, and every rule below is a case where a declared prefix
would otherwise have meant one thing to the reader and another to the proxy:

| Refused | Example | Why |
|---------|---------|-----|
| Blank, whitespace, or the bare `/` | `""`, `"/"`, `"///"` | An empty prefix matches *every* request and would turn the whole service anonymous — the worst outcome this feature can produce. |
| Unrooted | `welcome` | Not a path prefix. |
| An empty segment | `/a//b` | Not a legal route template. |
| A `.` or `..` segment | `/public/../admin` | Reads as scoped to `/public` while naming `/admin`. Refused rather than resolved, so a prefix always means what it spells. |
| Any character outside the permitted set | `/a{x}`, `/a*`, `/a?b`, `/a;b`, `/a:b`, `/a@b`, `/a\b` | `{`, `}` and `*` would make the router match `/aANYTHING/…` where the middlewares match only the literal. The rest are separators or delimiters to some parsers and literals to others. |
| Percent-encoding | `/public%2fadmin`, `/public/%2e%2e/admin` | A prefix whose meaning depends on encoding cannot be reasoned about — and these are the classic separator-smuggling and traversal forms. |
| Control characters or whitespace | `/a b`, `/a\tb` | Invisible differences between two entries that read identically, and the raw material of log and header injection. |
| Non-ASCII characters | `/públic` | The same path has more than one Unicode spelling (`NFC` vs `NFD`), so which one is anonymous would depend on how the configuration file was saved. |
| A path AuthProxy answers itself | `/.cratis`, `/.cratis/token`, `/_pages`, `/invite`, `/register`, `/signin-microsoft` | These do not become "more public" — they take the endpoint *away* from AuthProxy and hand it to a backend. |

A dot *inside* a segment is fine, so `/.well-known/acme-challenge` and `/public/health.json` are both
valid. Only a segment that is exactly `.` or `..` is refused.

A refused entry is reported at startup as a warning naming the entry and the reason, so a declared path
that still returns the selection page can be diagnosed from the log rather than by inspection.

`/api` chooses the endpoint the same way the authenticated routes do: a prefix under `/api` is served by
the service's `Backend`, anything else by its `Frontend`, falling back to whichever endpoint the service
actually declares.

### What it does and does not change

- The request still travels through AuthProxy. Inbound `x-ms-client-principal`,
  `x-ms-client-principal-id`, `x-ms-client-principal-name` and `Tenant-ID` headers are stripped as they
  are for every other request, so a caller cannot assert an identity on an anonymous path.
- No principal headers are injected for a caller with no session. A caller that *does* present a valid
  session is still authenticated normally and still gets its identity headers — the path is
  identity-*optional*, not identity-free.
- A signed-in caller reaches a declared path **without a `Tenant-ID` header** when they have not chosen a
  tenant, because tenant selection is skipped along with everything else. Handle a declared path as
  tenant-optional: it already has to work for a caller with no identity at all, so identity without a
  tenant is a strictly better-informed case of the same thing.
- The application remains responsible for authorizing these paths. This only stops the proxy from
  demanding a login before the application is ever reached.
- A declared prefix is claimed for the whole proxy. An anonymous caller cannot send a `Service-ID`
  header, so the path itself identifies the service — in a multi-service deployment no other service can
  serve anything under a declared prefix. If two services declare the same prefix, the first one in
  configuration order serves it; the path stays anonymous, which is what both asked for.
- A declared path is reachable for *every* caller, not only signed-out ones. Provider selection, the
  unresolved-tenant refusal and the tenant-selection page are all skipped for it, so a user who happens to
  be signed in — without having chosen a tenant — still gets the application's response rather than a
  chooser page.

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
on success, issues a bearer token scoped to the configured `RoutePrefix`, along with a refresh token
that can later be exchanged for a new access token without resupplying the client credentials.

This creates a one-to-one relationship between:

- the proxied service
- the route prefix the token may access
- the downstream endpoint that verifies the client credentials

The verification endpoint's response can optionally include a `tenant` property, which AuthProxy then
carries on the issued tokens and can resolve into the `Tenant-ID` header on proxied requests.
See [Back-channel client credentials](authentication.md#back-channel-client-credentials) for the full
token, tenant-resolution, and refresh-token flow.
