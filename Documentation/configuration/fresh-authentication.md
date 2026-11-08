---
title: Fresh Authentication
description: Require a recent sign-in before a service path can be used, and read the authentication time AuthProxy forwards to the backend.
---

# Fresh Authentication

A session can stay valid for days. For an operation such as changing a payout account or deleting data, you often want proof that the user signed in recently, not just that a session exists. Fresh authentication lets a service declare, per path, how old the user's sign-in may be.

It is opt-in. A service without `FreshAuthentication` behaves exactly as before.

## Configure a service

Set `Cratis:AuthProxy:Services:<name>:FreshAuthentication` to a list of rules:

```json
{
  "FreshAuthentication": [
    { "Path": "/settings/payout", "Methods": ["POST", "PUT"], "MaxAge": "00:05:00" },
    { "Path": "/admin", "Prefix": true, "MaxAge": "00:15:00" }
  ]
}
```

`Path` is relative to the service. With `Prefix` the rule also covers every descendant path; without it only the exact path matches. `Methods` limits the rule to the listed HTTP methods, and an empty list matches all of them. `MaxAge` defaults to five minutes and accepts values from one second to one day. Anonymous paths are never affected.

## What a caller sees

When the session's authentication is older than `MaxAge`, or its age is unknown, the request is not forwarded and the response depends on the caller:

- A browser navigation (a `GET` for a document) is redirected to sign in again with the same provider, then returns to the original page.
- Any other request receives `401` with `Cache-Control: no-store` and a `WWW-Authenticate: Bearer error="insufficient_user_authentication", max_age="<seconds>"` challenge. There is no redirect, and AuthProxy never replays the request after the user signs in again, so the client decides whether to retry.

A path that matches no rule is forwarded as usual.

## OpenID Connect providers

For an OpenID Connect provider, AuthProxy asks the provider to authenticate again by sending `prompt=login` and `max_age` with the sign-in request. It then checks the `auth_time` claim of the validated identity token and accepts the sign-in only when that time satisfies the requested age. A completion whose token carries no usable `auth_time` is refused when a recent sign-in was requested. The proven time is stored in the session.

## OAuth providers

An OAuth (non-OpenID Connect) provider cannot prove when the user signed in, and AuthProxy cannot force it to ask again. AuthProxy therefore records no authentication time for these sessions, and a path with a `FreshAuthentication` rule answers `403` with no redirect and no body. Reauthenticating cannot satisfy the limit, so do not put such a rule on a service whose users sign in with an OAuth provider.

An identity provider that never emits `auth_time` has the same effect: paths with a rule stay unusable for its users.

## What the backend receives

AuthProxy forwards the time it validated as an `auth_time` claim inside the signed `x-ms-client-principal` envelope, in Unix seconds:

```json
{ "type": "auth_time", "value": "1767225600" }
```

The claim is present only for a browser session whose authentication time AuthProxy validated. Bearer-token and on-behalf requests carry none.

A receiver should treat the claim as follows:

- The claim is trustworthy only when the [forwarded identity signature](forwarded-identity-signing.md) verifies. Without verification, any caller could write one.
- A missing claim means the time is unknown. Treat unknown as stale.
- Compare `auth_time` with the current time and your own limit; the claim states when, not whether it is recent enough.

The forwarding of a provider's own `auth_time` has changed. AuthProxy no longer forwards the value an identity provider put in its token. The claim the backend sees is always the time AuthProxy validated, and an `x-cratis-auth-time` header or an `auth_time` claim in a caller-supplied principal never reaches the backend.

## See also

- [Authorization](authorization.md)
- [Forwarded Identity Signing](forwarded-identity-signing.md)
