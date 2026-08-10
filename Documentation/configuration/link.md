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
4. **AuthProxy returns to the application — but only when the exchange succeeded.** On success the browser is
   redirected to the supplied `returnUrl`, where the application correlates the token back to the signed-in
   user, records the association, and closes the popup. If the exchange did not succeed — the endpoint is not
   configured, the link token or the provider subject could not be resolved, the endpoint was unreachable, or
   the application answered with a non-2xx status — the browser receives a generic link-failure page with
   HTTP `403` instead, and never the completion redirect. The page is the same for every cause, so it reveals
   nothing about which one occurred; the cause is logged for the operator. In every case the user's primary
   session is left exactly as it was.

The request body posted to `ExchangeUrl` depends on whether the selected provider opts into
[canonical federated identity](authentication.md#canonical-federated-identity).

Legacy providers keep the existing body:

```json
{ "subject": "<provider subject>", "identityProvider": "<issuer / provider>" }
```

Canonical providers add the stable provider-aware identity fields:

```json
{
  "subject": "<configured canonical subject>",
  "providerKey": "<configured stable provider key>",
  "issuer": "<normalized validated or configured issuer>",
  "identityProvider": "<same value as providerKey>"
}
```

with `Authorization: Bearer <one-time-link-token>`.

Canonical identity is opt-in per provider. During migration, the application endpoint must accept both
bodies. For a canonical body, bind the account with the complete `(providerKey, issuer, subject)` tuple;
never treat `subject` alone or the compatibility `identityProvider` field as the stable account key.
The tuple records provider authentication metadata only. The application still decides whether that identity
may link a credential to the current account.

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

When `ExchangeUrl` is empty or the `Link` section is absent, there is nowhere to post the subject, so the link
callback cannot complete: the browser receives the generic link-failure page (HTTP `403`) rather than the
completion redirect. The flow is effectively disabled, and it fails visibly rather than reporting success for
a link that was never recorded.

> **Security.** The JSON callback body is not signed. The one-time bearer token binds the operation to the
> signed-in application user, but it does not by itself prove that AuthProxy sent the HTTP request. Keep
> `ExchangeUrl` network-isolated from public traffic or authenticate AuthProxy separately at the application
> endpoint. Keep the token short-lived and single-use, and never turn successful provider authentication into
> application authorization without applying the application's own linking policy.
