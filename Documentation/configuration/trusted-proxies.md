# Trusted Proxies

AuthProxy almost never sees a browser. It sees an ingress controller, a load balancer, a service-mesh
sidecar, or a CDN edge — and everything it knows about the person on the other side comes from what that
thing wrote into `X-Forwarded-For` and `X-Forwarded-Proto`.

Those are ordinary request headers. Nothing about them is signed, and nothing about them is special: any
caller that can open a connection to AuthProxy can send whatever it likes in them. The question a reverse
proxy has to answer, before it believes a single one, is **which callers are allowed to speak for someone
else** — and that is a fact about your network that only your deployment knows.

This page is how you tell it.

---

## What is at stake

It is tempting to file forwarded headers under "logging detail". They are not. Two values decide a
surprising amount of AuthProxy's behavior:

| Value | What it decides |
|-------|-----------------|
| The client address | The `ipAddress` in every [sign-in notification](sign-in.md) — the record your application shows a user as "a new sign-in from 203.0.113.7" and acts on when it looks unfamiliar. |
| The request scheme | Whether every AuthProxy session cookie carries `Secure`; what the OIDC `post_logout_redirect_uri` claims your public origin to be; and which origins the [post-logout allow-list](logout.md) admits. |

A caller who can set the first one writes its own audit trail. A caller who can set the second one changes
whether a browser is willing to send your session cookies at all — and, in the other direction, whether a
genuinely encrypted session is protected as one.

---

## Declaring the boundary

Name the peers directly in front of AuthProxy:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Ingress": {
        "TrustedProxies": [ "10.0.0.0/8", "203.0.113.7" ],
        "ForwardLimit": 1
      }
    }
  }
}
```

Or, as environment variables in a container:

```bash
Cratis__AuthProxy__Ingress__TrustedProxies__0=10.0.0.0/8
Cratis__AuthProxy__Ingress__TrustedProxies__1=203.0.113.7
Cratis__AuthProxy__Ingress__ForwardLimit=1
```

Each entry is an IP address (`10.0.0.7`, `2001:db8::1`) or a CIDR range (`10.0.0.0/8`, `2001:db8::/32`).
A range written against a host address inside it — `10.0.0.1/8` — means the range, the same as everywhere
else. An entry AuthProxy cannot parse **fails startup and names the offending value**; it is never quietly
dropped, because a trusted proxy that is silently not trusted is a boundary silently in the wrong place.

The addresses to declare are the ones **AuthProxy sees as the peer**, not the addresses of your users. In
Kubernetes that is the ingress controller's pod CIDR; behind a cloud load balancer it is the balancer's
subnet; behind a CDN it is the CDN's published egress ranges.

---

## `ForwardLimit` decides which address is reported as the client

This is the part worth reading twice, because it is the setting most often left at whatever the sample had.

`X-Forwarded-For` grows left to right: the outermost proxy appends the address it accepted the connection
from, then the next one appends, and so on. AuthProxy therefore reads it **from the right**, consuming one
entry per hop, and `ForwardLimit` is how many hops it consumes. Whatever it lands on becomes the client
address — the one recorded against a sign-in.

Consider a request that reaches AuthProxy carrying `X-Forwarded-For: 198.51.100.9, 203.0.113.30` from a
peer at `203.0.113.10`:

| `ForwardLimit` | Reported client address | What that means |
|----------------|------------------------|-----------------|
| `1` (the default) | `203.0.113.30` | One hop consumed. Correct when a single ingress sits in front — but if there are really two, you are recording **your own inner proxy** as the client, identically for every user. |
| `2` | `198.51.100.9` | Two hops consumed. Correct when a CDN sits in front of a load balancer. |
| `3` | `198.51.100.9` | The chain ran out first. The surplus can never be reached, which is exactly the protection. |

So set it to the number of hops your deployment actually has:

- **Too low** and the reported address is your own infrastructure — the audit trail is real but useless.
- **Too high** and the reported address is whatever the outermost caller chose to write — the audit trail
  is attacker-controlled, which is worse than useless.

Every hop counted must itself be a trusted peer. AuthProxy re-checks at each step, so raising `ForwardLimit`
without also declaring the intermediate addresses in `TrustedProxies` changes nothing.

> [!IMPORTANT]
> **If you have more than one hop and have never set `ForwardLimit`, the address recorded against a sign-in
> changes with this release.** Read this even if you are not planning to configure anything.
>
> AuthProxy used to record the **left-most** entry of `X-Forwarded-For` for the sign-in notification, while
> everything else in the proxy used the address the forwarded-headers middleware had settled on. Those are
> two different answers to one question, and the left-most one is the entry furthest from you — the one the
> outermost caller wrote, which nothing verified. Both now come from the same place, the address the
> middleware settled on after consuming `ForwardLimit` hops.
>
> With `X-Forwarded-For: 198.51.100.7, 203.0.113.9` and the default `ForwardLimit` of `1`:
>
> | | Recorded `ipAddress` | What it is |
> |---|---|---|
> | Before | `198.51.100.7` | the browser — but taken on trust from the header |
> | Now | `203.0.113.9` | your own inner load balancer — one hop consumed |
>
> Nothing is broken and nothing is less safe; the new value is the honest one for a `ForwardLimit` of `1`.
> But every sign-in notification and audit record silently changes meaning, and if two hops really do sit in
> front of you the recorded address becomes identical for every user, which is useless as an audit trail.
>
> **To restore the browser's address, count the hops you actually have.** For the chain above that is
> `ForwardLimit: 2`, with the inner balancer's address declared in `TrustedProxies` so the second hop is
> allowed to be consumed:
>
> ```json
> {
>   "Cratis": {
>     "AuthProxy": {
>       "Ingress": {
>         "TrustedProxies": [ "203.0.113.9", "10.0.0.0/8" ],
>         "ForwardLimit": 2
>       }
>     }
>   }
> }
> ```
>
> Verify it the way [Checking your work](#checking-your-work) describes: sign in and look at the
> `ipAddress` your `SignIn:NotifyUrl` endpoint received.

---

## Modes

`Mode` decides how the trusted set is arrived at. `Configured` is the default and is what almost every
deployment wants.

```json
{
  "Cratis": {
    "AuthProxy": {
      "Ingress": {
        "Mode": "LoopbackOnly"
      }
    }
  }
}
```

| Mode | Trusts | Use it when |
|------|--------|-------------|
| `Configured` | Exactly the peers in `TrustedProxies` | Normal deployments. This is the default. |
| `LoopbackOnly` | Only a caller on the loopback interface | A sidecar, or local development. A deployment behind an ingress never sees loopback as the peer, so this refuses every forwarded header it receives. |
| `TrustAny` | Every caller | Nothing but your own ingress can reach AuthProxy at all — a private network with no other route in, or a listener with no peer address at all (see below). |

> [!WARNING]
> **Do not set `ASPNETCORE_FORWARDEDHEADERS_ENABLED`.** It is standard advice for containerized ASP.NET
> images, and it is the wrong thing here: it makes the host insert a forwarded-headers middleware of its
> own, ahead of every AuthProxy middleware, and clear the known-proxy lists while doing it. The peer
> AuthProxy records as the caller is then the one the header has already replaced, so the boundary you
> declared is applied to a request that was rewritten before AuthProxy saw it. AuthProxy consumes forwarded
> headers itself, from the configuration on this page — leave the variable unset. It logs a warning at
> startup if it finds it set.

### A listener with no peer address

`Configured` and `LoopbackOnly` both decide by looking at the peer's IP address. A Unix domain socket does
not have one — `RemoteIpAddress` is null — so every request over such a listener is treated as coming from
an untrusted peer. Sessions keep working, which is what makes this quiet: the visible symptom is that
`X-Forwarded-Proto` stops being honored, so cookies lose `Secure` and the public origin reverts to the
transport scheme.

If AuthProxy listens on a Unix socket, and the only thing that can write to that socket is your own
ingress, say `TrustAny`. That is what "the peer is trustworthy and cannot be identified by address" looks
like when it is stated rather than stumbled into.

---

## The compatibility fallback, and the warning

`Configured` with an **empty** `TrustedProxies` keeps the behavior AuthProxy has always had: every caller's
forwarded headers are believed. Upgrading breaks nothing.

It is not, however, silent. At startup AuthProxy logs a warning naming the mode it is running in and the
configuration key that leaves it:

```text
warn: AuthProxy is running in Configured trusted-proxy mode with no trusted proxies configured, so it
      believes the X-Forwarded-For and X-Forwarded-Proto headers of every caller. Set
      Cratis:AuthProxy:Ingress:TrustedProxies to the addresses or CIDR ranges of the ingress in front of
      it, or set Cratis:AuthProxy:Ingress:Mode to LoopbackOnly or TrustAny to state the choice explicitly.
      A future major release will refuse to start in this state.
```

> [!IMPORTANT]
> Treat the warning as a task, not as noise. A future major release turns this condition into a refusal to
> start. Declaring `TrustedProxies` — or stating `TrustAny` deliberately, if that genuinely describes your
> network — is what clears it.

If you truly do run somewhere nothing else can reach AuthProxy, say `TrustAny` rather than leaving the list
empty. The behavior is identical; the difference is that one of them is a decision somebody made and the
other is an omission nobody noticed.

---

## What a declared boundary changes

Once `TrustedProxies` is set, a request from a peer outside it is treated as what it is — a caller talking
directly to AuthProxy:

- `X-Forwarded-For` is ignored; the connection's real address is the client address.
- `X-Forwarded-Proto` is ignored; the real transport scheme decides cookie `Secure` and the public origin.
- The geo headers a fronting CDN adds — `CF-IPCountry`, `CF-Region`, `CF-IPCity`, and the conventional
  `X-Geo-*` / `X-AppEngine-*` city, region and country headers — resolve to an empty `location` in the
  sign-in notification, because from an untrusted caller they are values it chose rather than facts about
  where it is.

A request from a peer **inside** the boundary is honored exactly as before, for as many hops as
`ForwardLimit` allows.

Two headers are never honored, from any peer: `X-Forwarded-Host` and `X-Forwarded-Prefix`. AuthProxy
consumes only the address and the scheme, so neither the request host nor the path base can be moved by a
header. The RFC 7239 `Forwarded` header is likewise not consumed.

---

## Configuring it from Aspire

The [Aspire hosting integration](../aspire/index.md) writes the same configuration keys:

```csharp
var authProxy = builder.AddAuthProxy("authproxy")
    .WithTrustedProxies("10.0.0.0/8", "203.0.113.7")
    .WithForwardLimit(2);
```

`WithTrustedProxies` appends, so the peers can be declared wherever each one is known. An entry that is
neither an address nor a CIDR range is refused when the app host builds, rather than being carried to the
proxy and refused there.

---

## Checking your work

The address AuthProxy settled on is the one it reports in the sign-in notification, so the quickest
end-to-end check is to sign in and look at what your `SignIn:NotifyUrl` endpoint received:

- `ipAddress` should be the address of the machine you signed in from — not an address inside your cluster.
- `location` should be populated if, and only if, a fronting CDN is adding geo headers.

If `ipAddress` is one of your own proxies, raise `ForwardLimit` by one and add that proxy's address to
`TrustedProxies`. If it is an address you can influence from outside, `ForwardLimit` is too high.
