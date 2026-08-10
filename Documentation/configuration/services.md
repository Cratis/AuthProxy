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
| `ResolveIdentityDetails` | `bool?` | `true` when Backend is set | Whether to call `/.cratis/me` on this service **at all**. See [Identity enrichment](#identity-enrichment). |
| `IdentityVerification` | `BestEffort` \| `Required` | `BestEffort` | What that call's answer **means**. See [Identity enrichment](#identity-enrichment). |
| `IdentityVerificationTimeout` | `TimeSpan` | `00:00:10` | How long to wait for the answer. Zero or negative leaves the wait unbounded. |
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

Two how-to guides cover the cases in detail: [Public application surfaces](public-surfaces.md) for a page
or API a person reaches without an account, and [Receiving webhooks](webhooks.md) for a request from
another system.

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
The response is stored in a short-lived cookie (`.cratis-identity`) and injected as
the `x-ms-client-principal` header on every proxied request so that backend services can read
identity details without re-calling the identity endpoint themselves.

What exactly your service receives — the four identity headers, the guarantee that every value is
US-ASCII, the `x-ms-client-principal-name*` sibling for names that are not, and why
`x-ms-client-principal` stays the canonical value — is described in
[Forwarded identity headers](./authentication.md#forwarded-identity-headers).

### Two settings, two questions

`ResolveIdentityDetails` decides whether the endpoint is **called**. `IdentityVerification` decides what
its answer is **worth**. They are separate because they are separate questions, and they have opposite
failure directions.

Asking a service "what else do you know about this user" is enrichment: if the service is down, the right
answer is to carry on without the extra details. Asking it "is this user allowed in at all" is
verification: if the service is down, the only safe answer is no. A single flag cannot express both, so
the mode is per service.

| Mode | Meaning | Use for |
|------|---------|---------|
| `BestEffort` (default) | The endpoint enriches. Only an explicit `403` denies. | A service that contributes display details — profile, preferences, feature flags. |
| `Required` | The endpoint decides. Only an explicit positive admits. | The one service that genuinely answers with an authorization verdict. |

`BestEffort` is the released behavior and stays the default, so an existing deployment is unaffected.

### What each outcome does

| The service… | `BestEffort` | `Required` |
|--------------|--------------|------------|
| answers `200` with an unambiguous positive verdict | forward, merge details | forward, merge details |
| answers `403` | **deny** | **deny** |
| answers `200` with a verdict of "not authorized" | forward, merge details | **deny** |
| cannot be reached (DNS, connection refused, TLS) | forward | **deny** |
| does not answer within `IdentityVerificationTimeout` | forward | **deny** |
| is still answering when the caller goes away | forward | **deny** |
| answers any other non-`2xx` (400, 401, 404, 500, 502, 503…) | forward | **deny** |
| answers `204`, or `200` with an empty or blank body | forward | **deny** |
| answers a body that will not parse as JSON | forward | **deny** |
| answers well-formed JSON carrying no verdict | forward, merge details | **deny** |

An **unambiguous positive** is a body carrying `isAuthorized: true` as a JSON boolean, and not
contradicting it with `isAuthenticated: false`. A response that carries only details states no verdict — 
which is exactly right for a service being asked only to enrich, and never enough for one being asked to
decide. Property names are matched without regard to casing; a quoted `"true"` is not a verdict.

Where several services take part, **every** service in `Required` mode must answer with a positive.
Requirements add together and are never widened, the same way [service claim
requirements](authorization.md) compose. A `BestEffort` service failing alongside them costs the caller
nothing but the details it would have supplied.

### On every denial

AuthProxy serves the [forbidden page](../pages.md) at `403` and erases everything an earlier success left
behind: the sealed `.cratis-identity-authorization` record is cleared, the readable `.cratis-identity`
cookie is expired, and the in-memory result is evicted. Without that, the next request would present one
of them and skip the question that was just answered no.

The denial is logged with a bounded reason code (`TransportFailure`, `TimedOut`, `UnsuccessfulStatusCode`,
`NoVerdict`, …) and never with the response body, which is content from a system that knows who the
caller is.

### Turning the memory off

Two settings under [`Session`](authentication.md#session) bound how long an answer is reused:

- `IdentityResultCacheDuration` (default 30 seconds) — the proxy's own in-memory cache, which collapses a
  page load's burst of requests into one round-trip per user and tenant. Set it to zero to resolve on
  every request.
- `IdentityRevalidationInterval` (default 10 minutes) — how long the sealed authorization record is
  honored. Set it to zero for no bound. Under `Required`, "no bound" means **no record is written at
  all**, so every request is verified.

Both are the window in which a user whose access has just been revoked still gets through, so shorten them
deliberately: the cost is one identity-endpoint call per request per user.

```json
{
  "Cratis": {
    "AuthProxy": {
      "Session": {
        "IdentityResultCacheDuration": "00:00:05",
        "IdentityRevalidationInterval": "00:01:00"
      },
      "Services": {
        "portal": {
          "Backend": { "BaseUrl": "http://portal-api:8080/" },
          "IdentityVerification": "Required",
          "IdentityVerificationTimeout": "00:00:10"
        },
        "reporting": {
          "Backend": { "BaseUrl": "http://reporting-api:8080/" }
        }
      }
    }
  }
}
```

From Aspire:

```csharp
authProxy.WithIdentityVerification("portal", IdentityVerificationMode.Required);
```

> **Requiring verification makes that service a single point of failure, on purpose.** While it is down,
> nothing behind the proxy is served, because nobody can confirm who is allowed in. That is the trade the
> mode exists to make — take it only for a service that really does answer `/.cratis/me` with a verdict.

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
