# Logout

AuthProxy exposes a well-known logout endpoint that ends the current session and returns the user to a
validated destination:

```
GET /.cratis/logout?redirect=<absolute-url>
```

The endpoint is anonymous — it works even when the session is already invalid — and is handled before
the authentication challenge stages, so it never bounces the user to a login provider.

---

## What it clears

A logout request:

1. Signs the user out of the authentication cookie (`.Cratis.AuthProxy.Auth.v2`), including any chunked variants.
2. Deletes every AuthProxy session cookie:
   - `.cratis-identity`
   - `.cratis-tenant`
   - `.cratis-tenants`
   - `.cratis-invite`
   - `.cratis-registration`
   - `.cratis-providers`
3. Redirects (`302 Found`) to the validated `redirect` target.

---

## The `redirect` parameter

The post-logout destination is supplied as an **absolute URL** in the `redirect` query-string parameter,
for example:

```
/.cratis/logout?redirect=https://cratis.studio
```

Because the target is absolute, it cannot be validated with the relative-URL check used elsewhere.
Instead it is matched against an **allow-list of origins** so the endpoint can never be turned into an
open redirect. A target is allowed when its origin (scheme + host + port) matches any of:

- The proxy's **own public origin** as seen by the browser (derived from the request, honoring
  `X-Forwarded-Proto`). This covers redirecting back to the site the user is already on.
- Any configured **service frontend** (`Cratis:AuthProxy:Services:<name>:Frontend:BaseUrl`).
- The configured **lobby frontend** (`Cratis:AuthProxy:Invite:Lobby:Frontend:BaseUrl`).

Same-site **relative** URLs (a single leading `/`, but not `//`) are always allowed.

If `redirect` is missing, empty, or fails validation, AuthProxy falls back to the application root (`/`).

---

## Example

A "Log out" control in the application simply navigates the browser to the endpoint:

```html
<a href="/.cratis/logout?redirect=https://cratis.studio">Log out</a>
```

After the redirect the user lands on the target unauthenticated; requesting a protected resource then
triggers the normal login flow.
