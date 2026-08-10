# Management Listener

AuthProxy answers nothing about itself. There is no health endpoint, no readiness endpoint, no metrics
path — every port it opens is the internet-facing one, and every request on it goes through
authentication, tenancy and the reverse proxy. That is the right default for a proxy whose whole job is to
be the front door, and it leaves a deployment with nothing to probe.

The management listener is the opt-in answer: a **second, private socket** carrying two endpoints and
nothing else.

---

## What a probe is actually testing today

Without it, there are two things a deployment can point a probe at, and neither one says what it looks
like it says.

| Probe | What it proves |
|-------|----------------|
| A TCP socket check | A process accepted a connection. Nothing about whether configuration bound, whether the Data Protection key ring initialized, or whether a single authenticated request could be served. |
| An HTTP GET at an application path declared in [`AnonymousPaths`](services.md#anonymous-paths) | The proxy *and* that application are both working. Genuinely useful — but it fails when the application is down, which is not the same question as whether the proxy should be restarted. |

The gap is the middle case: an AuthProxy that starts, listens, and cannot serve anybody. A key ring that
will not initialize is exactly that — the process is healthy by every external sign, and every
authenticated request fails, because the key ring is what encrypts the session cookie and every
AuthProxy-issued token. A TCP probe reports it healthy and keeps sending it traffic.

---

## Turning it on

Name a port. Everything else has a default.

```json
{
  "Cratis": {
    "AuthProxy": {
      "Management": {
        "Port": 9110
      }
    }
  }
}
```

That opens `http://127.0.0.1:9110` alongside the listener AuthProxy already serves traffic on, and answers
two paths there:

| Path | Answers |
|------|---------|
| `/health/live` | `200` whenever the request loop is servicing requests. |
| `/health/ready` | `200` when this instance can serve traffic, `503` when it cannot. |

With Aspire:

```csharp
builder.AddAuthProxy("authproxy")
       .WithManagementListener(9110);
```

**Leaving the section out changes nothing.** No second socket is opened, neither path exists, and
AuthProxy binds exactly what it binds without this feature. This is a pure addition — there is nothing to
migrate.

---

## Settings

| Setting | Default | Meaning |
|---------|---------|---------|
| `Port` | *(none)* | The port the listener binds. **Required** — declaring the section without it is refused at startup. |
| `BindAddress` | `127.0.0.1` | The address it binds. |
| `LivePath` | `/health/live` | The path answering liveness. |
| `ReadyPath` | `/health/ready` | The path answering readiness. |

There is deliberately **no default port**. A port is a fact about your deployment: a value invented here
would either collide with something you run or turn a private surface into a well-known one.

The listener defaults to **loopback**, which is what makes it private. In Kubernetes that is reachable by
the kubelet's probes and by a sidecar in the same pod, and by nothing on the network. Widening
`BindAddress` publishes both endpoints to everything that can route to the address — do it only when the
probe genuinely runs elsewhere, and put a network policy in front of it.

---

## Liveness and readiness answer different questions

This distinction is the whole point of having two endpoints, and getting it backwards causes outages.

**Liveness consults nothing.** No dependency is resolved, no I/O is performed. It answers `200` for as long
as the process is servicing requests — including while storage, the identity provider and every backend
are unreachable. An orchestrator *restarts* what fails a liveness probe, so a liveness answer that depended
on a dependency would turn somebody else's outage into a restart loop of the one component that was still
working.

**Readiness verifies local capability only.** Today that means one thing: a `Protect`/`Unprotect`
round-trip through Data Protection, which is the only mechanism that forces the key ring to initialize and
proves it against the configured [`DataProtectionKeysPath`](authentication.md). It is re-run on every call
and no answer is cached, so a key ring that becomes unusable — a volume unmounted, a permission revoked —
changes the answer.

Readiness deliberately calls **no backend**, no `/.cratis/me` endpoint, no tenant-verification URL and no
OIDC authority. A deployment whose every backend is down still becomes ready, because pulling the proxy out
of rotation during a backend outage removes the component that would have served the error page.

---

## The endpoints are on that listener and nowhere else

Both directions are enforced, and both matter.

- **The management paths answer only on the management port.** Asking the public listener for
  `/health/live` gets the same `404` any unknown path gets. The private surface is not reachable from the
  internet, whatever the request claims.
- **The management port answers only the management paths.** Anything else on it — `/`, an API path,
  `/.cratis/providers`, a path you declared anonymous, a bundled asset — gets that same `404`, and is never
  handed to the middleware pipeline or the reverse proxy. Whatever can reach this port bypassed the ingress
  by definition; it does not get to use it as a way around authentication.

Isolation is decided by **the socket the request was accepted on**, not by the `Host` header. ASP.NET's own
port-scoping convention (`RequireHost("*:9110")`) matches that header, and a header is whatever the caller
typed — a request to the public listener carrying `Host: anything:9110` would otherwise be served from the
private surface.

### Your application keeps its own `/health`

Nothing under `/health` is reserved globally. A service that serves its own health path and declares it in
[`AnonymousPaths`](services.md#anonymous-paths) keeps having it proxied exactly as before:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Services": {
        "main": {
          "AnonymousPaths": ["/health"]
        }
      }
    }
  }
}
```

The one exception is the two exact management paths themselves. If your application serves something at
`/health/live` or `/health/ready` and you want both, point the management listener elsewhere:

```json
{
  "Management": {
    "Port": 9110,
    "LivePath": "/internal/alive",
    "ReadyPath": "/internal/serving"
  }
}
```

---

## What the endpoints say

Very little, on purpose. A management endpoint is reachable without a credential by design, so everything
it says is said to whoever can reach the port.

Every answer is a short fixed body — `live`, `ready`, `not ready`, or nothing at all for the `404` — and
names no provider, tenant, backend address, filesystem path, key identifier, version or assembly. A failing
readiness answer discloses no more than a succeeding one: the reason is written to the log, where an
operator reads it and a caller does not.

No answer carries `Set-Cookie` or `WWW-Authenticate`, and enabling the listener also stops Kestrel naming
itself in the `Server` header of every response AuthProxy writes.

---

## What is refused at startup

The failure mode this feature has to avoid is a deployment that looks configured and answers no probe. Each
of these is named at startup, pointing at the exact key:

| Configuration | Why it is refused |
|---------------|-------------------|
| The section with no `Port` | No listener opens, so every probe fails to connect — which reads exactly like the application being down. |
| A `Port` the public listener already binds | A private listener that shares the public one is not private. |
| A `Port` outside 1–65535 | Not a port. |
| A `LivePath` or `ReadyPath` that is not rooted | Matches no request, so the listener answers its own probe the uniform `404`. |
| `LivePath` and `ReadyPath` naming the same path | One of the two answers would be unreachable, and the one silently lost is readiness. |
| A blank `BindAddress` | Names no address. Leave it unset for the loopback default. |

The Aspire builder refuses an unusable port where the app host is built, so the mistake surfaces against
the line of code that made it rather than at deployment.

---

## Kubernetes

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 9110
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health/ready
    port: 9110
  periodSeconds: 5
```

The probe port must be declared as a container port for the kubelet to reach it, and it should **not** be
exposed through a Service.

---

## Replacing an existing probe

If you followed the guidance in [Unauthenticated Responses](unauthenticated-responses.md) and pointed a
probe at a declared anonymous path or downgraded it to TCP, this is the better answer for the proxy itself.
Keep an application-path probe if you have one — it tests the proxy *and* the application end to end, which
is a question worth asking — but point the *proxy's own* liveness and readiness here, where they mean what
their names say.
