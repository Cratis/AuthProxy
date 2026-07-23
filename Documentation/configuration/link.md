# Credential Linking

AuthProxy can let an **already signed-in** user prove control of an additional identity-provider login and
associate it with their existing account — without ever replacing their current session. This is the
proof-of-control building block behind an application's "add a credential" feature.

```
GET /.cratis/link/{scheme}?returnUrl=<relative-url>&token=<one-time-link-token>
```

It is deliberately **not** the same as `/.cratis/login/{scheme}`: login signs the authenticated identity into
the primary session cookie (which, for a second identity, would swap who the user is — effectively logging
them out of the original account). The link flow authenticates the second provider, captures its subject,
and hands that subject to the application, all while leaving the primary session untouched.

---

## Why a popup, not an iframe

The application opens `/.cratis/link/{scheme}` in a **popup** (or a top-level redirect), never a nested
iframe. Provider consent pages send `X-Frame-Options: DENY`, and AuthProxy's authentication and OAuth
correlation/nonce cookies are `SameSite=Lax`, so a cross-site iframe cannot complete the flow. A same-origin
popup avoids both problems.

---

## How it works

1. **The application mints a one-time link token.** When the user starts "add a credential", the application
   issues a short-lived, single-use token bound to that signed-in user, and opens the popup at
   `/.cratis/link/{scheme}?returnUrl=…&token=…`. The `scheme` is a configured provider scheme (the same value
   used by `/.cratis/login/{scheme}`, e.g. `github`).
2. **AuthProxy challenges the provider.** The request must come from an authenticated session (an anonymous
   request is rejected with `401`; an unknown scheme with `404`; a missing token with `400`). AuthProxy starts
   an OAuth/OIDC challenge for the requested scheme, carrying a link-mode marker and the link token through the
   authentication properties.
3. **On the provider callback the identity is captured, not signed in.** Instead of writing the primary
   authentication cookie, AuthProxy reads the freshly authenticated `subject` (and identity provider) and
   `POST`s them to the configured [`ExchangeUrl`](#configuration), authenticated with the link token as the
   bearer credential — exactly mirroring the [invite exchange](./lobby/invitation-to-organization.md). The
   user's original session is preserved.
4. **AuthProxy returns to the application.** The browser is redirected to the supplied `returnUrl`, where the
   application correlates the token back to the signed-in user, records the association, and closes the popup.

The request body posted to `ExchangeUrl` matches the invite exchange shape:

```json
{ "subject": "<provider subject>", "identityProvider": "<issuer / provider>" }
```

with `Authorization: Bearer <one-time-link-token>`.

---

## The `returnUrl` parameter

`returnUrl` is echoed back to the browser after the link completes, so it is constrained to a **same-site
relative path** (a single leading `/`, but not `//`). Anything else — including an absolute URL to another
origin — falls back to the application root (`/`), so the endpoint can never be turned into an open redirect.

---

## Configuration

Set the application endpoint that records the freshly authenticated subject under
`Cratis:AuthProxy:Link:ExchangeUrl`. It is the link counterpart of `Cratis:AuthProxy:Invite:ExchangeUrl`.

```json
{
  "Cratis": {
    "AuthProxy": {
      "Link": {
        "ExchangeUrl": "https://studio.example.com/api/internal/identity-providers/link"
      }
    }
  }
}
```

Equivalent environment variable:

```
Cratis__AuthProxy__Link__ExchangeUrl=https://studio.example.com/api/internal/identity-providers/link
```

When `ExchangeUrl` is empty or the `Link` section is absent, the link callback is skipped (the subject is not
posted anywhere) and the flow is effectively disabled.

> **Security.** The exchange endpoint is a service-to-service back-channel: it is reachable by AuthProxy, not by
> browsers, and it trusts the subject AuthProxy delivers from a real provider authentication together with the
> one-time link token — never a client-supplied subject. Point `ExchangeUrl` at an internal application address
> and keep the token short-lived and single-use, exactly as for the invite exchange.
