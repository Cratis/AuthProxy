---
title: One proxy, several hosts
description: Put several applications on their own hosts behind one AuthProxy and one sign-in, with a shared session cookie and a single identity-provider callback.
---

Say you run a console, an operations tool and a Chronicle workbench, each on its own host. Today that
means three AuthProxy instances, three OAuth apps (or three callback URLs on one app), and three sign-ins:
a person who signs in to the console is signed out on `operations.example.com`. This page puts all three
behind one AuthProxy with one sign-in.

It is a how-to for someone who already runs AuthProxy. For the individual settings, see
[Services](services.md), [Authentication](authentication.md#session-lifetime-and-re-validation) and
[Logout](logout.md).

## What you end up with

| Host | Service | Who may use it |
|------|---------|----------------|
| `console.example.com` | `console` | Any signed-in person |
| `operations.example.com` | `operations` | Members of `Cratis/operations` |
| `chronicle.example.com` | `chronicle` | Any signed-in person |
| `auth.example.com` | none — runs the sign-in handshake | Everyone (optional, see [step 4](#4-run-every-handshake-on-one-host)) |

A request for a host reaches that host's service, and that service's own
[authorization requirements](authorization.md) apply to it. One session cookie, scoped to `.example.com`,
is honored on every host.

## 1. Give each service its hosts

```json
{
  "Cratis": {
    "AuthProxy": {
      "Services": {
        "console": {
          "Hosts": [ "console.example.com" ],
          "Frontend": { "BaseUrl": "http://console-web:3000/" },
          "Backend": { "BaseUrl": "http://console-api:8080/" }
        },
        "operations": {
          "Hosts": [ "operations.example.com" ],
          "Frontend": { "BaseUrl": "http://operations-web:3000/" },
          "Backend": { "BaseUrl": "http://operations-api:8080/" },
          "Authorization": {
            "RequiredClaims": [ { "Claim": "urn:github:team", "AnyOf": [ "Cratis/operations" ] } ]
          }
        },
        "chronicle": {
          "Hosts": [ "chronicle.example.com" ],
          "Frontend": { "BaseUrl": "http://chronicle-web:3000/" },
          "Backend": { "BaseUrl": "http://chronicle-api:8080/" }
        }
      }
    }
  }
}
```

AuthProxy refuses to start when two services claim the same host, or when a host is not a plain host name
with an optional port. See [Routing by host or path prefix](services.md#routing-by-host-or-path-prefix) for
the precedence rules.

From Aspire:

```csharp
authProxy
    .WithHosts("console", "console.example.com")
    .WithHosts("operations", "operations.example.com")
    .WithHosts("chronicle", "chronicle.example.com");
```

### What your ingress has to do

AuthProxy routes on the `Host` header it receives, so the ingress in front of it must forward every host
to AuthProxy **and preserve the original `Host` header**. An ingress that rewrites it to one internal name
sends every request to the same service. Set
[`AllowedHosts`](https://learn.microsoft.com/aspnet/core/fundamentals/servers/kestrel/host-filtering) to the
host names you serve, as well: it is the setting that makes AuthProxy answer only for them. AuthProxy
warns at startup when a cookie domain is set and `AllowedHosts` accepts every host.

## 2. Share the session

```json
{
  "Cratis": {
    "AuthProxy": {
      "Session": {
        "CookieDomain": ".example.com"
      }
    }
  }
}
```

From Aspire: `authProxy.WithSessionCookieDomain(".example.com")`.

The cookie now carries `Domain=.example.com`, so the browser sends it to every host under it. Choose the
narrowest domain that covers your hosts. A domain cookie also goes to hosts that are **not** behind
AuthProxy, and a broad domain such as `.com` widens who can replay it. AuthProxy refuses to start when:

- a service declares a host outside the domain;
- the domain is an IP address, a top-level domain, a wildcard, or has a port;
- [tenants are resolved by `SubHost`](#why-the-cookie-domain-is-refused-with-subhost-tenancy).

Nothing else about the session changes: the lifetime, the re-validation and the identity cookies behave as
described in [Authentication](authentication.md#session-lifetime-and-re-validation). The services' own
authorization still decides what each host lets a person do, so a session issued for `console` does not
open `operations` for someone without the `Cratis/operations` claim.

## 3. Register the provider callbacks

Without a callback host, every host runs its own handshake, so the identity provider has to know the callback of
each one. For a GitHub OAuth app that provider is registered under the scheme `github`, and the callbacks are:

```text
https://console.example.com/signin-github
https://operations.example.com/signin-github
https://chronicle.example.com/signin-github
```

Register all of them, or use a provider that accepts a wildcard redirect address. The post-logout address
works the same way: each host's `/.cratis/logout/callback` has to be registered with a provider that signs
out at the provider.

That is the whole setup when you only need one sign-in. If registering a callback per host is the part you
want to get rid of, continue.

## 4. Run every handshake on one host

```json
{
  "Cratis": {
    "AuthProxy": {
      "SignIn": {
        "CallbackHost": "auth.example.com"
      }
    }
  }
}
```

From Aspire: `authProxy.WithSignInCallbackHost("auth.example.com")`.

A sign-in that starts on `chronicle.example.com` is sent to `auth.example.com`, runs the whole handshake
there, and returns to the page the person asked for on `chronicle.example.com`. The provider needs one
callback, `https://auth.example.com/signin-github`, and one post-logout address. The session cookie is the
one from step 2, so the person arrives signed in.

`CallbackHost` needs `Session:CookieDomain`, and the host has to lie inside it; AuthProxy refuses to start
otherwise. `auth.example.com` does not have to be declared as a service, but it has to reach AuthProxy.

### Where a sign-in may return to

An absolute return address is an open redirect waiting to happen, so AuthProxy honors one **only** when a
callback host is configured, and only when all of these hold:

- the origin belongs to a host a service declares, or to a configured frontend, lobby or
  [`Logout:AllowedRedirectOrigins`](logout.md#allowing-additional-post-logout-origins) entry;
- the host lies inside the cookie domain, so the session follows the person there;
- for a declared host, the scheme is the one the request arrived on and the port is the one the host declares, so an HTTPS sign-in is never returned to HTTP;
- there is no user information in the address.

Anything else is reduced to its path on the host the sign-in started on, or to `/`. Sign-out uses the same
list. Without a callback host, return addresses are relative paths exactly as before.

### Invitations, links and registration stay on their host

Invitation, credential-link and registration flows start their own challenge on the host the person is on,
with cookies that belong to that host alone. A callback host does not move them, and the provider has to
accept the callback of every host where one can start. If you only register the callback host, send people
into those flows from that host.

## Migrating from several instances

The old instances each issued their own host-only cookie, usually under the default name. After the move,
a browser can hold the old host-only cookie and the new shared one under the same name. AuthProxy deletes
the stale copy for you:

- when a new session is issued, after the new cookie is written;
- when a person signs out;
- when the browser sends the session cookie twice;
- when a session cookie arrives that cannot be read.

It only ever deletes the host-only copy, never the shared one. If the request is for the cookie domain
itself (for example `example.com` with `.example.com`), the browser may not distinguish the two, so nothing
is deleted there.

Three more things help:

- **Rename the cookie.** `Session:CookieName` (Aspire: `WithSessionCookieName`) gives the new session its own
  name, so it can never be confused with an old one, and lets two AuthProxy deployments share a parent
  domain without reading each other's sessions. Changing it signs everyone out once, and the old
  default-named cookie is deleted on the next sign-in and sign-out. The `__Host-` prefix is refused with a
  cookie domain, because browsers do not accept a domain on such a cookie.
- **Delete cookies other deployments left.** [`Logout:AdditionalCookies`](logout.md#clearing-additional-cookies)
  removes cookies AuthProxy does not own, including ones scoped to the parent domain.
- **Watch header size.** A cookie on the parent domain travels with every request to every host under it.
  Sessions that carry many claims are chunked into several cookies, and an ingress with a small header
  limit (nginx `large_client_header_buffers`) can answer `400` for a browser that still holds the old
  chunks too. Raise the limit during the migration.

## Why the cookie domain is refused with SubHost tenancy

With the [`SubHost` strategy](tenancy.md#subhost-strategy-options) each tenant lives on its own subdomain,
and the host-only cookie is what keeps a session for one tenant off the next tenant's host. A cookie shared
across the domain would carry it to all of them, and the tenant check only confirms that a tenant
exists, not that the person belongs to it. AuthProxy therefore refuses to start with both, and there is no
setting to override that. Resolve tenants some other way, or keep the host-only cookie.

## Limits to know about

- **A host is a default, not a boundary.** A service-selection header or `?service=` still wins over the
  host, as it always has, so a frontend on one host can call another service's backend by naming it. The
  other service's authorization requirements apply to that call, so it cannot do anything the person could
  not do there, but its responses are readable by scripts on the first host. If two applications must not
  read each other's data, they must not share an AuthProxy.
- **`SameSite=Lax` does not separate sibling subdomains.** They are the same site, so a request from
  `console.example.com` to `operations.example.com` carries the cookie. Treat every host under the cookie
  domain as inside the same trust boundary.
- **The `Host` header is the ingress's to protect.** AuthProxy trusts the host it receives. Set `AllowedHosts`
  and keep the [trusted-proxy boundary](trusted-proxies.md) declared.

## Check your work

1. Sign in on `console.example.com`, then open `chronicle.example.com` in the same browser. You should be
   signed in, without a provider redirect.
2. Open `operations.example.com` as someone without the claim. You should get the forbidden page, not the
   application.
3. Sign out on `chronicle.example.com`, then reload `console.example.com`. You should be signed out there too.
4. With a callback host, start a sign-in on `chronicle.example.com` and watch the address bar: it visits
   `auth.example.com` and ends on the page you asked for.
5. In the browser's cookie storage, look for the session cookie on each host. There should be one, with
   `Domain=.example.com`, and no host-only copy.
