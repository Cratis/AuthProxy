# Credential Linking

AuthProxy can let an **already signed-in** user prove control of an additional identity-provider login and
associate it with their existing account — without ever replacing their current session. This is the
proof-of-control building block behind an application's "add a credential" feature.

```
GET /.cratis/link?token=<one-time-link-token>                                  → embeddable provider-selection page
GET /.cratis/link/{scheme}?returnUrl=<relative-url>&token=<one-time-link-token> → challenge for one provider
GET /.cratis/link/complete                                                     → completion page
```

It is deliberately **not** the same as `/.cratis/login/{scheme}`: login signs the authenticated identity into
the primary session cookie (which, for a second identity, would swap who the user is — effectively logging
them out of the original account). The link flow authenticates the second provider, captures its subject,
and hands that subject to the application, all while leaving the primary session untouched.

---

## Embedding the flow in the application

The flow is designed to run inside a **modal iframe** on the application's own page. There is one hard
constraint it is built around: the provider leg cannot be framed. External identity providers
(`login.microsoftonline.com`, `accounts.google.com`, …) send `X-Frame-Options: DENY` /
`frame-ancestors 'none'` on their sign-in pages, so any challenge honored inside an iframe leaves a dead
frame. The flow is therefore split:

- **The iframe shows AuthProxy pages only.** The application embeds `/.cratis/link?token=…` — the
  provider-selection page. It lists the configured providers and, on a click, opens
  `/.cratis/link/{scheme}` with `window.open` — a separate **top-level** window where the provider
  authenticates. AuthProxy enforces this shape server-side: a navigation to `/.cratis/link/{scheme}` whose
  `Sec-Fetch-Dest` says it is framed is answered with the selection page instead of a challenge.
- **The provider window reports back over a `BroadcastChannel`.** The completion page
  (`/.cratis/link/complete`, where the flow ends by default) and the failure page broadcast
  `{ type: 'cratis:credential-link-complete' }` / `{ type: 'cratis:credential-link-failed' }` on the
  same-origin channel `cratis.credential-link` — deliberately not `window.opener`, which an identity
  provider's `Cross-Origin-Opener-Policy` can sever mid-flow. The completion window then closes itself.
- **The framed page signals the parent with `postMessage`.** On either outcome the selection page forwards
  the message to `window.parent`, targeted at the configured embed ancestor origins (never `*`), so the
  application can close its modal and refresh — or leave the modal open for a retry after a failure.

Embedding is **off by default**. The link pages send `Content-Security-Policy: frame-ancestors 'none'`
(plus `X-Frame-Options: DENY`) until the deployment names the origins allowed to frame them:

```
Cratis__AuthProxy__Link__EmbedAncestors__0=self
```

`self` means the proxy's own origin — the common case, where the application is served through the proxy.
Additional entries may name other origins (e.g. `https://app.example.com`). This setting opens the **link
pages only**; sign-in and selection pages always refuse framing, and proxied application responses are
never touched.

Opening `/.cratis/link/{scheme}` directly in a popup or top-level redirect — the pre-embedding shape —
still works exactly as before.

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
4. **AuthProxy ends the flow — completion only when the exchange succeeded.** On success the browser is
   redirected to the supplied `returnUrl`, or to the flow's own completion page (`/.cratis/link/complete`)
   when none was supplied — which broadcasts the outcome and closes the window. If the exchange did not
   succeed — the endpoint is not configured, the link token or the provider subject could not be resolved,
   the endpoint was unreachable, or the application answered with a non-2xx status — the browser receives a
   generic link-failure page with HTTP `403` instead, and never the completion redirect. The page is the
   same for every cause, so it reveals nothing about which one occurred; the cause is logged for the
   operator. A failed provider round-trip (correlation failure, provider error, the person cancelling)
   ends on the same failure page — never on the sign-in selection page, whose full sign-ins would offer to
   replace the very session the link was preserving. In every case the user's primary session is left
   exactly as it was.

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
origin — falls back to the flow's own completion page (`/.cratis/link/complete`), so the endpoint can never
be turned into an open redirect. Omitting `returnUrl` lands on the completion page too, which is the right
default for the embedded flow.

---

## Configuration

Set the application endpoint that records the freshly authenticated subject under
`Cratis:AuthProxy:Link:ExchangeUrl`. It is the link counterpart of `Cratis:AuthProxy:Invite:ExchangeUrl`.

```json
{
  "Cratis": {
    "AuthProxy": {
      "Link": {
        "ExchangeUrl": "https://studio.example.com/api/internal/identity-providers/link",
        "EmbedAncestors": ["self"]
      }
    }
  }
}
```

Equivalent environment variables:

```
Cratis__AuthProxy__Link__ExchangeUrl=https://studio.example.com/api/internal/identity-providers/link
Cratis__AuthProxy__Link__EmbedAncestors__0=self
```

`EmbedAncestors` names the origins allowed to embed the link pages in an iframe (see
[Embedding the flow in the application](#embedding-the-flow-in-the-application)); when empty — the default —
the link pages refuse framing entirely.

When `ExchangeUrl` is empty or the `Link` section is absent, there is nowhere to post the subject, so the link
callback cannot complete: the browser receives the generic link-failure page (HTTP `403`) rather than the
completion redirect. The flow is effectively disabled, and it fails visibly rather than reporting success for
a link that was never recorded.

> **Security.** The JSON callback body is not signed. The one-time bearer token binds the operation to the
> signed-in application user, but it does not by itself prove that AuthProxy sent the HTTP request. Keep
> `ExchangeUrl` network-isolated from public traffic or authenticate AuthProxy separately at the application
> endpoint. Keep the token short-lived and single-use, and never turn successful provider authentication into
> application authorization without applying the application's own linking policy.
