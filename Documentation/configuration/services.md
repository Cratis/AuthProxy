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
| `Hosts` | `string[]` | `[]` | Host names (with an optional port) that route to this service. See [Routing by host or path prefix](#routing-by-host-or-path-prefix). |
| `PathPrefix` | `string` | `""` | Path prefix that routes to this service, for example `/reporting`. See [Routing by host or path prefix](#routing-by-host-or-path-prefix). |
| `StripPathPrefix` | `bool` | `false` | Remove `PathPrefix` from the forwarded path and send it in `X-Forwarded-Prefix`. |
| `ResolveIdentityDetails` | `bool?` | `true` when Backend is set | Whether to call `/.cratis/me` on this service **at all**. See [Identity enrichment](#identity-enrichment). |
| `IdentityVerification` | `Required` \| `BestEffort` | `Required` | What that call's answer **means**. `Required` fails closed; `BestEffort` is the explicit opt-in for an endpoint that only enriches. See [Identity enrichment](#identity-enrichment). |
| `IdentityVerificationTimeout` | `TimeSpan` | `00:00:10` under `Required` (the default), unbounded under `BestEffort` | How long to wait for the answer. Zero or negative leaves the wait unbounded. See [Two settings, two questions](#two-settings-two-questions). |
| `ActivityTimeout` | `TimeSpan` | The root `ActivityTimeout`, then `00:05:00` | How long a request proxied to this service may sit idle before AuthProxy cancels it. See [Timeouts and streaming](#timeouts-and-streaming). |
| `AnonymousPaths` | `string[]` | `[]` | Path prefixes on this service served to unauthenticated callers. See [Anonymous paths](#anonymous-paths). |
| `ClientCredentials` | `ServiceClientCredentialsConfig` | `null` | Enables back-channel client-credentials verification and token minting for this service. |
| `BearerRoutes` | `BearerRouteConfig[]` | `[]` | Path prefixes authenticated by an access token from an external authorization server instead of a browser session. See [Bearer routes](#bearer-routes). |

### ServiceEndpointConfig properties

| Property | Type | Description |
|----------|------|-------------|
| `BaseUrl` | `string` | Base URL of the endpoint (e.g. `http://my-service:8080/`). |
| `ActivityTimeout` | `TimeSpan` | Idle limit for this endpoint alone (`Backend` or `Frontend`). Overrides the service and root values. See [Timeouts and streaming](#timeouts-and-streaming). |

### ServiceClientCredentialsConfig properties

| Property | Type | Description |
|----------|------|-------------|
| `RoutePrefix` | `string` | Route prefix that AuthProxy-issued bearer tokens are allowed to access (for example `/api`). |
| `VerificationPath` | `string` | Internal verification endpoint. Relative values are resolved against `Backend.BaseUrl`; absolute values are used as-is. |

---

## Routing

### Single service

When only one service is configured, and it declares neither `Hosts` nor a `PathPrefix`, AuthProxy adds a
plain catch-all route so the service is reachable without any special routing header or query parameter.

- `/{**path}` → frontend
- `/api/{**path}` → backend

### Multiple services

With more than one service, a request reaches a service when the service declares the request's host or
path prefix (see below), or when the client names the service with one of:

| Mechanism | Example |
|-----------|---------|
| `x-cratis-microservice` request header | `x-cratis-microservice: portal` |
| `service` query parameter | `?service=portal` |

`x-cratis-microservice` is the header an Arc frontend sends for HTTP requests when it sets a microservice.
The `Service-ID` header earlier releases used is still accepted inbound and means the same thing;
`x-cratis-microservice` wins when both are sent. A header naming an unknown service does not match a route,
so a valid `?service=` can still select the target and its authorization requirements.

Arc's WebSocket and SSE observable connections instead send `?x-cratis-microservice=` by default.
AuthProxy does not route on that query argument yet. In a multi-service deployment, configure Arc with
`Globals.microserviceWSQueryArgument = 'service';` so observable connections use `?service=`.
The selected identifier is forwarded under both header names, including when selected by `?service=`.
Forwarding `Service-ID` is deprecated and will be removed in a future major release; move backends to
`x-cratis-microservice`.

Routes are matched case-insensitively. Within a service, `/api/...` goes to the backend and everything else
goes to the frontend. With host routing, path-prefix routing or the unrestricted single-service catch-all,
a service with only a backend receives every path within that route. Header and query selection of a
backend-only service only match `/api/...`.

### Routing by host or path prefix

A browser cannot put a header on a top-level navigation, and adding `?service=` to every URL (assets, deep
links, bookmarks) is impractical. To put several applications behind one AuthProxy, and so behind one
sign-in, give each service a host, a path prefix, or both:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Services": {
        "portal": {
          "Hosts": [ "portal.example.com" ],
          "Frontend": { "BaseUrl": "http://portal-web:3000/" },
          "Backend": { "BaseUrl": "http://portal-api:8080/" }
        },
        "reporting": {
          "PathPrefix": "/reporting",
          "StripPathPrefix": true,
          "Frontend": { "BaseUrl": "http://reporting-web:3000/" },
          "Backend": { "BaseUrl": "http://reporting-api:8080/" },
          "ClientCredentials": { "RoutePrefix": "/reporting/api" }
        }
      }
    }
  }
}
```

Here `https://portal.example.com/orders` goes to the portal frontend, `https://portal.example.com/api/orders` to
the portal backend, `https://portal.example.com/reporting/api/sales` to the reporting backend as `/api/sales`,
and `https://any-host/reporting/dashboard` to the reporting frontend as `/dashboard`.

#### Precedence

When more than one rule could match a request, the first one in this list wins:

1. [Anonymous paths](#anonymous-paths).
2. A `PathPrefix` on one of the service's `Hosts`.
3. A `PathPrefix` on a service without `Hosts`, which matches on every host.
4. The `x-cratis-microservice` header (or legacy `Service-ID`), then the `service` query parameter.
5. `Hosts` on a service without a `PathPrefix`.
6. The single-service catch-all routes.

A path prefix claims its part of the URL, so it wins over a header or query parameter naming another
service. A host is only a default for the requests on it: a frontend served from `portal.example.com` can
still call another service's backend by naming it in `x-cratis-microservice`, as Arc frontends do.

The service a request is routed to is also the service whose [authorization requirements](authorization.md)
apply to it, and the only service whose [client-credentials](#client-credentials) tokens it accepts. The
checks use the selected proxy route, so a host or prefix cannot be used to reach a service without
meeting its requirements. Client-credentials `RoutePrefix` must include the external path prefix; see
[Client credentials](#client-credentials).

#### Ambiguous matches fail at startup

AuthProxy refuses to start, and names the services involved, when:

- two services without a `PathPrefix` declare the same host (`example.com` without a port overlaps every
  `example.com:port`);
- two services declare equal or nested path prefixes (`/reports` and `/reports/archive`) on the same hosts, or
  both on every host;
- a `Hosts` entry is not a host name with an optional numeric port. URLs, paths, IPv6 literals and wildcards
  (`*.example.com`) are refused;
- a `PathPrefix` is not a rooted path of literal segments, is `/api` or below it, or covers a path AuthProxy
  reserves for itself (`/.cratis`, `/_pages`, `/invite`, `/register`, `/signin-*`);
- a service declares `Hosts` or a `PathPrefix` but has no `Backend` or `Frontend`, or sets `StripPathPrefix`
  without a `PathPrefix`.

A prefix on some hosts and a prefix on every host may overlap. The host-specific one wins on its hosts.

#### Keeping or stripping the prefix

By default the service receives the path as requested, `/reporting/api/sales`, and serves itself under the
prefix. In ASP.NET Core that is `app.UsePathBase("/reporting")`, and a single-page frontend builds with the
same base path.

With `StripPathPrefix` the prefix is removed: the service receives `/api/sales`, and AuthProxy sends the
removed prefix in `X-Forwarded-Prefix`. A backend that honors forwarded headers restores the removed prefix
as its path base, so links and redirects it generates still point under `/reporting`. An `X-Forwarded-Prefix`
sent by a proxy in front of AuthProxy is replaced, not combined. [Anonymous paths](#anonymous-paths) below a stripped prefix are
stripped too. Declare them with the full path, for example `/reporting/public`.

AuthProxy's own endpoints (`/.cratis/login`, `/.cratis/select-provider`, `/.cratis/logout` and the other
`/.cratis/*` paths it answers itself) stay at the root on every host. A frontend served under a prefix calls
them at the root. `/reporting/.cratis/me` is forwarded to the reporting service like any other path under
its prefix.

WebSocket upgrades and server-sent events follow the same routes as any other request.


---

## Timeouts and streaming

Everything AuthProxy forwards — a plain request, a WebSocket session, a Server-Sent Events (SSE) stream —
is subject to one limit, the **activity timeout**: the longest a proxied request may sit idle, with no bytes
moving in either direction, before AuthProxy cancels it. The clock restarts whenever data is read or
written, so it is an idle limit, not a cap on how long a connection may live. The default is five minutes.

Set it in three places. The most specific one that is set wins:

| Setting | Applies to |
|---------|------------|
| `Cratis:AuthProxy:Services:<name>:<Backend or Frontend>:ActivityTimeout` | That endpoint only. |
| `Cratis:AuthProxy:Services:<name>:ActivityTimeout` | Both endpoints of that service. |
| `Cratis:AuthProxy:ActivityTimeout` | Every endpoint that states nothing narrower. |

```json
{
  "Cratis": {
    "AuthProxy": {
      "ActivityTimeout": "00:10:00",
      "Services": {
        "portal": {
          "Backend": { "BaseUrl": "http://portal-api:8080/", "ActivityTimeout": "01:00:00" },
          "Frontend": { "BaseUrl": "http://portal-web:3000/" }
        },
        "reporting": {
          "Backend": { "BaseUrl": "http://reporting-api:8080/" },
          "ActivityTimeout": "00:02:00"
        }
      }
    }
  }
}
```

Here `portal`'s backend allows an hour of silence, its frontend and anything not listed allow ten minutes,
and `reporting` allows two. As environment variables the root value is `Cratis__AuthProxy__ActivityTimeout`
and a service's is `Cratis__AuthProxy__Services__portal__ActivityTimeout`.

A value must be at least one millisecond and at most 2,147,483,647 milliseconds (about 24 days).
AuthProxy refuses to start when a value is outside this range, and the message names the setting.
`Registration` is not a proxied endpoint: setting `Registration:ActivityTimeout` also prevents startup.
Remove that setting and configure the service's `Backend` or `Frontend` activity timeout instead.
`Invite:Lobby` does not create proxy clusters: setting `ActivityTimeout` on the lobby itself or its
`Backend`, `Frontend` or `Registration` endpoints also prevents startup with a message naming the setting.
Remove those settings and configure the proxied service under `Services` instead.
A change to the configuration file is applied to new requests without a restart.

From Aspire:

```csharp
authproxy.WithActivityTimeout(TimeSpan.FromMinutes(10));
authproxy.WithServiceActivityTimeout("reporting", TimeSpan.FromMinutes(2));
```

### WebSocket and Server-Sent Events

AuthProxy forwards a WebSocket upgrade or an SSE response to the service as-is and does not buffer, compress
or rewrite the stream, so each message reaches the client as soon as the service writes and flushes it. What
to know:

- **A quiet stream is cut.** If the service sends nothing for longer than the activity timeout, and the
  client sends nothing either, AuthProxy cancels the request and the client sees the connection drop. For a
  live-update feature such as an observable query, either send a heartbeat (an SSE comment line such as
  `: ping`, or a WebSocket ping) more often than the timeout, or raise the timeout above the longest silence
  you expect. A heartbeat at a third to a half of the timeout leaves room for one lost beat.
- **A stream is authorized when it opens.** The session cookie and any access policy are evaluated on the
  upgrade or SSE request, and the identity headers are attached to it. Nothing is re-checked while the
  stream stays open, so a user whose access is revoked keeps a connection that is already open until it
  closes. Keep streams bounded, or have the service close them periodically, if that window matters.
- **Whatever sits in front of AuthProxy has its own idle limit.** A load balancer, gateway or hosting
  platform in front of AuthProxy applies its own timeout, and the shortest limit on the path wins. Raising
  the AuthProxy value alone does not help if the platform cuts the connection first, so align the two, or
  rely on heartbeats that are more frequent than both.
- **The same applies behind AuthProxy.** A service or sidecar between AuthProxy and the application may
  have an idle limit of its own.
- **Reconnect on the client.** Browsers reconnect an `EventSource` on their own; a WebSocket client needs
  its own reconnect logic. A dropped stream is the normal way an idle one ends.

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
actually declares. Under a service's `PathPrefix`, the same split applies relative to that prefix: an
anonymous `/reporting/api/webhook` goes to the reporting backend.

### What it does and does not change

- The request still travels through AuthProxy. Inbound `x-ms-client-principal`,
  `x-ms-client-principal-id`, `x-ms-client-principal-name` and `x-cratis-tenant-id` (and the legacy
  `Tenant-ID`) headers are stripped as they
  are for every other request, so a caller cannot assert an identity on an anonymous path.
- No principal headers are injected for a caller with no session. A caller that *does* present a valid
  session is still authenticated normally and still gets its identity headers — the path is
  identity-*optional*, not identity-free.
- A signed-in caller reaches a declared path **without an `x-cratis-tenant-id` header** when they have not chosen a
  tenant, because tenant selection is skipped along with everything else. Handle a declared path as
  tenant-optional: it already has to work for a caller with no identity at all, so identity without a
  tenant is a strictly better-informed case of the same thing.
- The application remains responsible for authorizing these paths. This only stops the proxy from
  demanding a login before the application is ever reached.
- A declared prefix is claimed for the whole proxy. An anonymous caller cannot send an `x-cratis-microservice`
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
| `Required` (default) | The endpoint decides. Only an explicit positive admits. | Any service that answers `/.cratis/me` with an authorization verdict. |
| `BestEffort` | The endpoint enriches. Only an explicit `403` denies. | A service that contributes display details — profile, preferences, feature flags — and that you accept being asked in vain. |

`Required` is the default for every service that has a `Backend` and has not set `ResolveIdentityDetails`
to `false`: a proxy that does not know whether its identity service is up must not assume the answer is
yes. A service that is never called — no `Backend`, or `ResolveIdentityDetails: false` — has no answer to
fail, so the setting has no effect on it.

`BestEffort` is an explicit opt-in. Under it the proxy reads no verdict out of a successful response body at
all, it takes `details` and forwards the caller, so a body saying `"isAuthorized": false` is **not** a
refusal — the caller is admitted and those details are merged. Plenty of services answer that for reasons
that are not about access at all: an account mid-onboarding, a lapsed trial, a profile the frontend renders
a banner for. Opt in only when that is what you mean. Earlier releases defaulted to `BestEffort`; see
[Upgrading](../upgrading/identity-verification-required-by-default.md) for what changed and how to keep the
old behavior.

`Required` also decides how long the call may take. See [What each outcome does](#what-each-outcome-does)
for the timeout that follows from it.

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
| answers `200` with contradicting verdicts | forward, merge details | **deny** |

An **unambiguous positive** is a body carrying `isAuthorized: true` as a JSON boolean, and not
contradicting it with `isAuthenticated: false`. A response that carries only details states no verdict —
which is exactly right for a service being asked only to enrich, and never enough for one being asked to
decide. Property names are matched without regard to casing; a quoted `"true"` is not a verdict.

Read the `BestEffort` column as one sentence: **`403` denies, everything else is forwarded and whatever
details arrived are merged.** That is what earlier releases did for every service, and it is why it is now an
opt-in rather than the default: it admits a caller exactly when the proxy has learned the least.

### How long the call may take

`IdentityVerificationTimeout` states the wait. Leave it unset and the mode decides, because a bound on the
wait is a property of a decision, not of enrichment:

| Mode | Unset timeout means |
|------|---------------------|
| `Required` (default) | Ten seconds. A service standing between a caller and a decision has to fail in bounded time — otherwise a service that accepts connections and then stops answering holds every authenticated request open for a minute and a half each. |
| `BestEffort` | Unbounded — the ambient 100-second HTTP client default. A slow enrichment service still gets to answer, because cutting it off would not refuse anybody, it would admit them with that service's details silently missing. |

A timeout you **do** state is honored in both modes. The wait is also bound to the caller's own request
lifetime either way, so a client that disconnects stops occupying the proxy.

Where several services take part, **every** service in `Required` mode must answer with a positive.
Requirements add together and are never widened, the same way [service claim
requirements](authorization.md) compose. A `BestEffort` service failing alongside them costs the caller
nothing but the details it would have supplied.

### On every denial

AuthProxy serves the [forbidden page](well-known-pages.md) at `403` and erases everything an earlier success left
behind: the sealed `.cratis-identity-authorization` record is cleared, the readable `.cratis-identity`
cookie is expired, and the in-memory result is evicted. Without that, the next request would present one
of them and skip the question that was just answered no.

Set `Cratis:AuthProxy:Session:TerminateOnIdentityDenial` to `true` when a denial should also end the local
AuthProxy session.
AuthProxy signs out of its authentication cookie and clears the identity, authorization, tenant, invitation,
registration, provider-selection, transient authentication, and configured additional logout cookies before
serving the same `403`. It retains capability-entry and in-progress logout state, and does not initiate logout
at the external identity provider. The default is `false`, which preserves the authenticated session exactly
as earlier releases did.

> [!IMPORTANT]
> Two of those three erasures are *requests to the browser*, not guarantees. Clearing a cookie means
> sending a `Set-Cookie` that expires it, and a non-browser caller is free to ignore it and keep presenting
> the sealed record it was issued. So what `Required` bounds is **revocation latency**, not reuse: a
> positive can be replayed for at most `IdentityRevalidationInterval` (the sealed record) or
> `IdentityResultCacheDuration` (the proxy's own cache), whichever applies, and no longer. Shorten them to
> shorten that window — or set `IdentityRevalidationInterval` to zero, which under `Required` means no
> record is sealed at all and every request is verified.

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
          "IdentityVerificationTimeout": "00:00:10"
        },
        "reporting": {
          "Backend": { "BaseUrl": "http://reporting-api:8080/" },
          "IdentityVerification": "BestEffort"
        }
      }
    }
  }
}
```

`portal` states no mode, so it is `Required`; `reporting` only enriches and says so.

From Aspire, `Required` needs no call. Opt a service out explicitly:

```csharp
authProxy.WithIdentityVerification("reporting", IdentityVerificationMode.BestEffort);
authProxy.WithSessionTerminationOnIdentityDenial();
```

> **Requiring verification makes that service a single point of failure, on purpose.** While it is down,
> nothing behind the proxy is served, because nobody can confirm who is allowed in. That is the trade the
> default makes — and a backend that does not implement `/.cratis/me` with a verdict must either say
> `BestEffort` or set `ResolveIdentityDetails` to `false`.

### `Required` needs a tenant resolution

Identity is resolved per **user and tenant**, so a verdict is always a verdict about somebody in some
tenant. A deployment with no [tenant resolution](tenancy.md) configured resolves no tenant for anybody — so
there is nothing to verify against, on every request, for everyone.

AuthProxy therefore **refuses to start** when a service is `Required` — which includes a service that states no
mode, since `Required` is the default — and `TenantResolutions` is empty, and the message names the key and
the two ways out for a service that only enriches. Nothing about the alternative looks broken from the outside: the
proxy starts, people sign in, requests are forwarded, and the only thing that does not happen is the check
you asked for. A single-tenant deployment satisfies this with the `Specified` strategy:

```json
{
  "Cratis": {
    "AuthProxy": {
      "TenantResolutions": [
        { "Strategy": "Specified", "Options": { "TenantId": "00000000-0000-0000-0000-000000000000" } }
      ]
    }
  }
}
```

At request time the same principle applies: an authenticated caller whose tenant does not resolve is
**refused**, not waved through. There is one deliberate exemption — a path listed in
[`AnonymousPaths`](#anonymous-paths) is declared to be served without a session at all, so no verdict is
demanded for it and the application stays responsible for authorizing it, exactly as that setting already
says. AuthProxy's own sign-in, invite and registration surfaces are also exempt, because they are answered
by the proxy and never forwarded to a service; a signed-in caller with no organization has to be able to
reach the provider-selection page.

---

## Client credentials

When `ClientCredentials` is configured for a service, AuthProxy exposes `POST /.cratis/token`.
That endpoint forwards the supplied client credentials to the service's verification endpoint and,
on success, issues a bearer token scoped to the configured `RoutePrefix`, along with a refresh token
that can later be exchanged for a new access token without resupplying the client credentials.

`RoutePrefix` defaults to `/api` and is checked against the incoming path, before `StripPathPrefix` removes
anything. For a service with `PathPrefix: /reporting`, set `ClientCredentials.RoutePrefix` to
`/reporting/api` to accept bearer tokens on its API routes (or another explicitly permitted external
prefix). Host routing can distinguish services that share the same `RoutePrefix`.

This creates a one-to-one relationship between:

- the proxied service
- the route prefix the token may access
- the downstream endpoint that verifies the client credentials

The verification endpoint's response can optionally include a `tenant` property, which AuthProxy then
carries on the issued tokens and can resolve into the `x-cratis-tenant-id` header on proxied requests.
See [Back-channel client credentials](authentication.md#back-channel-client-credentials) for the full
token, tenant-resolution, and refresh-token flow.

---

## Bearer routes

A bearer route is a path prefix on a service that is called by programs — a CLI, an MCP client, another
service — with an access token issued by an external authorization server such as Cratis Identity. AuthProxy
stays a relying party: it validates the token and forwards the request, and it never issues these tokens.

```json
{
  "Cratis": {
    "AuthProxy": {
      "Authorization": {
        "RequiredClaims": [
          { "Claim": "urn:github:team", "AnyOf": [ "Cratis/direct" ] }
        ]
      },
      "Services": {
        "direct": {
          "Backend": { "BaseUrl": "http://direct:8080/" },
          "Frontend": { "BaseUrl": "http://direct:8080/" },
          "BearerRoutes": [
            {
              "PathPrefix": "/mcp",
              "Issuers": [ { "Issuer": "https://auth.example/" } ],
              "Audiences": [ "direct-api" ],
              "RequiredScopes": [ "direct:read" ],
              "ResourceMetadataUrl": "https://cratis.direct/.well-known/oauth-protected-resource/mcp",
              "IdentityProvider": "github",
              "ClaimMappings": {
                "sub": "github_id",
                "preferred_username": "github_login"
              },
              "IgnoreDeploymentRequiredClaims": true,
              "AcceptWithoutIdentityVerification": true
            },
            {
              "PathPrefix": "/v1",
              "Issuers": [ { "Issuer": "https://auth.example/" } ],
              "Audiences": [ "direct-api" ],
              "ResourceMetadataUrl": "https://cratis.direct/.well-known/oauth-protected-resource/v1",
              "IdentityProvider": "github",
              "ClaimMappings": {
                "sub": "github_id",
                "preferred_username": "github_login"
              },
              "IgnoreDeploymentRequiredClaims": true,
              "AcceptWithoutIdentityVerification": true
            }
          ]
        }
      }
    }
  }
}
```

This is Direct's shape: Cratis Identity issues tokens with `aud=direct-api` for both `https://cratis.direct/mcp`
and `https://cratis.direct/v1`. The claim mappings make a token-authenticated request carry the same
`x-ms-client-principal-id` (the numeric GitHub id) and `x-ms-client-principal-name` (the GitHub login) as a
browser session signed in through Direct's GitHub provider, so Direct resolves the same user either way. The
Cratis account id from the token's `sub` is still forwarded, as the `urn:cratis:bearer:subject` claim.

Direct's deployment also requires the `urn:github:team` claim. A browser session gets it from Direct's GitHub
sign-in, which reads team membership from the GitHub API; a Cratis Identity access token does not carry it. Claim
requirements apply to bearer routes by default, so without `IgnoreDeploymentRequiredClaims` every token on these
routes would be refused with `403`. With it, the proxy-wide and service requirements are left out on the route,
AuthProxy logs a warning at startup naming them, and Direct's backend is what decides whether the caller is a member
of the tenant. When Cratis Identity mints a team or membership claim, either remove
`IgnoreDeploymentRequiredClaims` (if the claim is `urn:github:team` itself), or keep it and require the new claim
on the route:

```json
"RequiredClaims": [
  { "Claim": "urn:cratis:membership", "AnyOf": [ "direct" ] }
]
```

`AcceptWithoutIdentityVerification` states the same thing for `/.cratis/me`: Direct answers it for browser
sessions, a bearer route never calls it, and Direct's backend checks the caller's membership of the tenant on
every token-authenticated request instead.

### BearerRouteConfig properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `PathPrefix` | `string` | — | The prefix this route covers, for example `/mcp`. Matched case-insensitively on segment boundaries, with the same rules as [anonymous paths](#what-a-valid-entry-looks-like). The longest matching prefix wins. |
| `Issuers` | `BearerIssuerConfig[]` | — | The authorization servers whose tokens are accepted. At least one. |
| `Audiences` | `string[]` | — | The token's `aud` must name at least one of these. At least one. |
| `RequiredScopes` | `string[]` | `[]` | Scopes the token must carry, every one of them. |
| `ResourceMetadataUrl` | `string` | `null` | Absolute URL of the RFC 9728 protected-resource metadata document. Named in every challenge; its path is forwarded to the backend without authentication and must be outside every bearer-route prefix. |
| `TenantClaimType` | `string` | `tid` | The token claim the tenant is read from. See [Tenancy](tenancy.md#bearer-routes). |
| `ClaimMappings` | `map<string, string>` | `{}` | Forwarded claim type → token claim it is read from, replacing all case variants of the target. A missing source refuses the token; mapped `sub`, `preferred_username` and `name` require one usable source value. Targets may not differ only by case or overwrite the route's tenant claim. Claim types containing `:` cannot be keys, because `:` separates configuration sections. |
| `IdentityProvider` | `string` | `bearer` | The identity provider named in the forwarded principal. |
| `ForwardAuthorizationHeader` | `bool` | `false` | Whether the backend also receives the `Authorization` header. |
| `ClockSkew` | `TimeSpan` | `00:00:30` | Allowed clock skew for `exp` and `nbf`. At most `00:05:00`. |
| `RequiredClaims` | `{ Claim, AnyOf }[]` | `[]` | Claim requirements of the route's own, checked against the token's principal after `ClaimMappings`, in addition to the deployment's. Same shape and rules as [`Authorization:RequiredClaims`](authorization.md); a requirement on a role claim is refused at startup, because a token never carries a role. |
| `IgnoreDeploymentRequiredClaims` | `bool` | `false` | Leave the deployment's claim requirements — proxy-wide and the service's — out on this route. For a deployment whose requirements name a claim the token issuer does not mint. Logged as a warning at startup. |
| `AcceptWithoutIdentityVerification` | `bool` | `false` | State that this route's callers are accepted without any service's `/.cratis/me` being asked about them. Required when a service declares `IdentityVerification: Required`; under `BestEffort` it silences the startup warning. See [What a bearer route changes](#what-a-bearer-route-changes). |

### BearerIssuerConfig properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Issuer` | `string` | — | The issuer identifier. The token's `iss` and the issuer metadata's `issuer` must both be exactly this value. HTTPS, or plain HTTP on a loopback host for development. |
| `MetadataAddress` | `string` | RFC 8414 address | The metadata document. Defaults to `/.well-known/oauth-authorization-server` inserted between the issuer's host and path. An OpenID Connect discovery document works too. |
| `TokenTypes` | `string[]` | `at+jwt`, `application/at+jwt` | Accepted JWT `typ` header values, so an ID token cannot be presented as an access token. |

### What a bearer route changes

- A request on a bearer route is answered before static files, authentication, provider selection, tenant
  selection and identity enrichment — none of them apply. [Admission](admission.md) and the trusted-proxy
  boundary run first and apply as to any request.
- The deployment's [claim requirements](authorization.md) — proxy-wide and the route's service's — apply to
  the token's principal after `ClaimMappings`, unless the route sets `IgnoreDeploymentRequiredClaims`. The
  route's own `RequiredClaims` apply on top either way. A token that does not satisfy them is refused with `403`.
  A requirement on a role can never be met: roles are dropped from every token.
- A bearer route **never calls `/.cratis/me`**, in either identity-verification mode: the endpoint answers for
  browser sessions, not for principals authenticated by a token. The backend must enforce tenant membership.
  - Under explicitly configured `BestEffort`, a `403` from a service's `/.cratis/me` refuses a browser session but not a
    token. AuthProxy starts, and logs a warning for each bearer route in a deployment where some service answers
    `/.cratis/me`, unless the route sets `AcceptWithoutIdentityVerification: true`.
  - Under `Required` (the default), AuthProxy **refuses to start** with a bearer route unless the route sets
    `AcceptWithoutIdentityVerification: true`.

  Setting it is the operator's statement that, on this route, the validated token, its scopes and the claim
  requirements are the whole decision at the edge and the backend answers for the rest.
- An accepted request is forwarded straight to the service **backend**, whichever of the service's endpoints
  would otherwise serve that path, with its path and query unchanged. AuthProxy adds no `Service-ID` header; one
  the caller sent is passed through like any other request header that is not an identity header.
- The session cookie is never read, and the `Cookie` header is not forwarded.
- A request whose path on the route still carries percent-encoding after the server has decoded it (such as an
  encoded `/`), a backslash, a `;` anywhere in it, repeated `/` separators, or a `.` or `..` segment is refused with `400` before its token
  is read: a backend that decoded or normalized it differently would receive a principal vouched for at a path
  that is not a bearer route. The `;` starts a path parameter, which Tomcat, Jetty and Spring strip before
  resolving dot segments, so they read `/mcp/..;/api/items` as `/api/items`. Repeated separators can hide a
  stricter nested route from AuthProxy while a backend collapses them, so `/v1//admin` is refused too.
- Every refusal is an API-style `400`, `401`, `403` or `503` — or `405` for a method other than `GET` or `HEAD`
  on the `ResourceMetadataUrl` path — never a redirect or a page. See
  [Bearer routes](authentication.md#bearer-routes-access-tokens-from-an-authorization-server).
- A token from a bearer-route issuer is refused with `401` on every path that is **not** one of the issuer's
  bearer routes, even where another bearer scheme (the [JWT Bearer](authentication.md#jwt-bearer-api) handler)
  would accept it. A browser-only surface such as `/api` stays browser-only.
- A route that overlaps an anonymous path, repeats another route's prefix, names no issuer or audience, or
  belongs to a service without a backend is refused at startup, as is one that does not accept callers without
  identity verification in a deployment that requires it.
- With no bearer route configured, nothing changes.
