# Logout

AuthProxy exposes a well-known logout endpoint that ends the current session and returns the user to a
validated destination:

```
GET /.cratis/logout?redirect=<absolute-url>
```

The endpoint is anonymous — it works even when the session is already invalid — and is handled before
the authentication challenge stages, so it never bounces the user to a login provider.

---

## Full-chain logout

A plain cookie logout leaves the user signed in at the identity provider, so the next visit silently
re-authenticates. To avoid that, AuthProxy performs a **full-chain logout**: it ends the session both
locally *and* at the identity provider using OIDC [RP-initiated logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).

When the session was established through an **OIDC provider**, a logout request:

1. Reads the stored `id_token` and the provider the session was established with from the authentication
   cookie, and clears the local session (see [What it clears](#what-it-clears)).
2. Redirects (`302 Found`) the browser to that provider's **end-session endpoint** (discovered from the
   provider's OpenID configuration) with:
   - `id_token_hint` — the stored `id_token`, so the provider knows which session to end.
   - `post_logout_redirect_uri` — AuthProxy's own callback, `/.cratis/logout/callback`.

   The validated final `redirect` target is carried across the round-trip in a short-lived, HTTP-only
   cookie (`.cratis-logout`) rather than in the URL.
3. The identity provider ends its own session and redirects back to `/.cratis/logout/callback`.
4. The callback clears every AuthProxy cookie again (idempotent) and redirects (`302 Found`) to the
   validated final `redirect` target.

> **Register the callback with each OIDC provider.** `post_logout_redirect_uri` must be allow-listed at
> the provider, so register `https://<your-proxy-host>/.cratis/logout/callback` as a permitted
> post-logout redirect URI for every OIDC application.

### OAuth 2.0 providers (e.g. GitHub)

OAuth 2.0 providers have no standard OIDC end-session endpoint and cannot be force-logged-out via a
redirect. When the session was established through an OAuth provider — or when there is no active OIDC
session, or the provider's discovery document advertises no end-session endpoint — AuthProxy falls back to
a **local-only logout**: it clears its own cookies and redirects straight to the validated `redirect`
target. The user's session at the OAuth provider is left untouched, so a later visit may still
re-authenticate silently without asking for credentials. This is a limitation of the OAuth providers, not
of AuthProxy.

---

## What it clears

Both the local logout and the post-logout callback:

1. Sign the user out of the authentication cookie (`.Cratis.AuthProxy.Auth.v2`), including any chunked variants.
2. Delete every AuthProxy session cookie:
   - `.cratis-identity`
   - `.cratis-tenant`
   - `.cratis-tenants`
   - `.cratis-invite`
   - `.cratis-registration`
   - `.cratis-providers`

The `.cratis-logout` carry cookie is deleted by the callback once the final target has been read from it.

---

## The `redirect` parameter

The post-logout destination is supplied as an **absolute URL** in the `redirect` query-string parameter,
for example:

```
/.cratis/logout?redirect=https://cratis.studio
```

Because the target is absolute, it cannot be validated with the relative-URL check used elsewhere.
Instead it is matched against an **allow-list of origins** so neither the endpoint nor its callback can be
turned into an open redirect. The target is validated on both legs of the round-trip. A target is allowed
when its origin (scheme + host + port) matches any of:

- The proxy's **own public origin** as seen by the browser (derived from the request, honoring
  `X-Forwarded-Proto`). This covers redirecting back to the site the user is already on.
- Any configured **service frontend** (`Cratis:AuthProxy:Services:<name>:Frontend:BaseUrl`).
- The configured **lobby frontend** (`Cratis:AuthProxy:Invite:Lobby:Frontend:BaseUrl`).
- Any origin listed in **`Cratis:AuthProxy:Logout:AllowedRedirectOrigins`** (see below).

Same-site **relative** URLs (a single leading `/`, but not `//`) are always allowed.

If `redirect` is missing, empty, or fails validation, AuthProxy falls back to the application root (`/`).

---

## Allowing additional post-logout origins

The implicit origins above cover redirecting back to the app itself, but a deployment often wants to send
the user somewhere else after logout — for example a separate marketing or landing site that is neither
the proxy's own origin nor a configured frontend. List those origins under
`Cratis:AuthProxy:Logout:AllowedRedirectOrigins`. Each entry is an absolute origin (scheme + host,
optionally a port) with no path; malformed or non-HTTP(S) entries are ignored.

```json
{
  "Cratis": {
    "AuthProxy": {
      "Logout": {
        "AllowedRedirectOrigins": [
          "https://cratis.studio"
        ]
      }
    }
  }
}
```

Equivalent environment variables (one indexed key per entry):

```
Cratis__AuthProxy__Logout__AllowedRedirectOrigins__0=https://cratis.studio
```

With the example above, `GET /.cratis/logout?redirect=https://cratis.studio` is permitted even when the
app itself is served from a different host such as `https://app.cratis.studio`.

---

## Example

A "Log out" control in the application simply navigates the browser to the endpoint:

```html
<a href="/.cratis/logout?redirect=https://cratis.studio">Log out</a>
```

For an OIDC session the browser is taken through the provider's end-session endpoint and back via the
callback; for an OAuth session it lands on the target directly. Either way the user ends up on the target
unauthenticated at AuthProxy, and requesting a protected resource then triggers the normal login flow.
