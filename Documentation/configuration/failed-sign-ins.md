# Failed Sign-ins

A sign-in that leaves AuthProxy for an identity provider can come back broken: the provider round-trip
fails validation (a stale correlation cookie, an expired state in another tab, a replayed callback URL),
or the person cancels the sign-in at the provider. AuthProxy never surfaces any of these as an error
page — the browser is redirected back to the provider-selection page (`/.cratis/select-provider`) with a
machine-readable reason, and the transient handshake cookies that poison retries are cleared along the
way.

---

## The `reason` parameter

The selection page is opened with a `reason` query-string parameter describing what happened:

| Reason | Meaning |
|--------|---------|
| `remote-failure` | The provider callback could not be validated — correlation failed, the OAuth state was missing or invalid, or the provider reported an error. |
| `access-denied` | The identity provider reported that access was denied — typically the person cancelled the sign-in or declined the consent prompt. |
| `invalid-session` | An authenticated session could no longer be turned into a forwardable identity, so it was terminated and a fresh sign-in is required. |

The bundled `select-provider.html` shows a matching message above the provider buttons; a custom page
(see [Well-Known Pages](well-known-pages.md)) can rely on the same contract. When the original
destination is known it is carried along in `returnUrl` (validated as same-site relative), so a
successful retry still lands where the person was heading.

With a **single** configured provider a failed sign-in still lands on the selection page rather than
being challenged again automatically — an immediate re-challenge would loop straight back into the very
handshake that failed. The person sees the reason and retries deliberately.

---

## Handshake-cookie hygiene

Every provider handshake writes transient correlation and nonce cookies
(`.AspNetCore.Correlation.*`, `.AspNetCore.OpenIdConnect.Nonce.*`). Abandoned and half-cleared
handshakes leave them behind, and a browser full of stale handshake cookies is exactly what makes the
next sign-in fail correlation. AuthProxy clears every one it can see:

- on **every failed** provider callback (this page's redirect),
- on **every successful** provider callback — one successful sign-in heals a poisoned browser,
- on [logout](logout.md).

On the provider callback path the deletion is issued for both the root path and the callback path
itself, which also reaches cookies written by older AuthProxy versions that scoped them to the callback
path — those are invisible to the logout endpoint and would otherwise accumulate forever.

---

## Sessions that cannot be forwarded

A proxied request must either carry the full identity headers or not be proxied at all. Authorization
guarantees that a protected route is only reached by an authenticated session, but building the
forwardable client principal can still fail closed — for example when
[canonical identity](authentication.md#canonical-federated-identity) resolution refuses the session
after a configuration change. Instead of forwarding such a request with no identity headers (which the
backend refuses, leaving the application blank while the person is "signed in"), AuthProxy terminates
the session — signing out and clearing every AuthProxy cookie — and answers:

- a browser navigation with a redirect to the selection page carrying `reason=invalid-session` and the
  original destination as `returnUrl`;
- any other caller with `401 Unauthorized`.

Routes a service declares in `AnonymousPaths` are exempt — they are proxied without identity by design.
