---
title: "On-behalf Sessions"
description: "Let support act on behalf of one user in one tenant while your application confirms a live grant, with both identities forwarded and signed."
---

An on-behalf session lets a support person, or an agent working for support, signed in with **their own**
identity, act on behalf of one specific user in one specific tenant, for one issue. Your application decides
whether that is allowed: AuthProxy only issues the session after the application confirms a live grant, asks again
while the session lasts, and tells the application when the session starts and ends.

The represented user's own sign-in is never used or required, and the actor never sees their credentials.

The feature is off by default. Without an `OnBehalf` section, AuthProxy's on-behalf endpoints answer `404`, no
grant check is ever made and nothing is forwarded differently.

This page is the contract between AuthProxy and the application that grants on-behalf access. It covers:

- [How a session works](#how-a-session-works)
- [Starting and ending a session](#starting-and-ending-a-session) (AuthProxy endpoints the support tool calls)
- [What the application implements](#what-the-application-implements): the grant check and the session notifications
- [What the application receives on every request](#what-the-application-receives-on-every-request)
- [Verifying AuthProxy's tokens](#verifying-authproxys-tokens)
- [Configuration](#configuration)
- [Security notes](#security-notes)

---

## How a session works

1. The actor signs in to AuthProxy as themselves, as usual, and satisfies the deployment's normal
   [authorization](authorization.md) requirements.
2. The actor's tool `POST`s `/.cratis/on-behalf/start` with the tenant, the subject of the user to represent, and
   the issue. AuthProxy checks the actor against `OnBehalf:ActorAuthorization`.
3. AuthProxy calls the application's **grant check**. Only an explicit live answer continues.
4. AuthProxy calls the application's **session started** notification. Only an acknowledged start continues.
5. AuthProxy writes the `.cratis-on-behalf` cookie. From now on, each request from that browser is forwarded as
   the represented user, with the actor and a signed assertion beside it.
6. AuthProxy trusts a live answer for at most `OnBehalf:RecheckInterval` (30 seconds by default), and never past
   the grant's `validUntil` or the session's maximum lifetime. After that it asks again.
7. The session ends when the actor ends it, the grant check says the grant is gone, the grant expires, the
   maximum lifetime passes, the actor signs out or another user signs in, or the application refuses the
   represented user's identity. AuthProxy then calls the **session ended** notification once, with the reason.

---

## Starting and ending a session

These endpoints are answered by AuthProxy itself and are never forwarded to a service. Every answer is JSON with
`Cache-Control: no-store`. A refusal has the body `{ "error": "<code>" }`.

### `POST /.cratis/on-behalf/start`

The request must be authenticated as the actor and must have a JSON body:

```http
POST /.cratis/on-behalf/start
Content-Type: application/json

{ "tenant": "<tenant id>", "subject": "<represented user's subject>", "issue": "<issue id>" }
```

Each value is required, at most 256 characters, with no surrounding whitespace or control characters.
`subject` must not be the actor's own subject.

On success, `200 OK` with the `.cratis-on-behalf` cookie set:

```json
{
  "sessionId": "<opaque session id>",
  "tenant": "<tenant id>",
  "subject": "<represented user's subject>",
  "issue": "<issue id>",
  "startedAt": "2026-09-01T12:00:00+00:00",
  "expiresAt": "2026-09-01T13:00:00+00:00",
  "grantValidUntil": "2026-09-01T12:45:00+00:00"
}
```

| Status | `error` | Meaning |
|---|---|---|
| `400` | `invalid-request` | The body is missing, malformed, or names the actor themselves. |
| `401` | `unauthenticated` | Nobody is signed in, or the actor's identity cannot be forwarded. |
| `403` | `actor-not-permitted` | The actor does not satisfy `OnBehalf:ActorAuthorization`. |
| `403` | `not-granted` | The application said there is no live grant, or it has expired. |
| `404` | `not-enabled` | The `OnBehalf` section is not configured. |
| `409` | `session-active` | This browser already has an on-behalf session. End it first. |
| `415` | `json-required` | The body is not `application/json`. |
| `503` | `unavailable` | The grant could not be confirmed, or the application did not acknowledge the start. Nothing was issued. |

### `POST /.cratis/on-behalf/end`

Ends the session the request carries, notifies the application and removes the cookie. It answers `204 No
Content`, including when there was no session. When the application did not acknowledge the end notification
the session has still ended, and the answer is `502` with `ended-not-acknowledged`.

### `GET /.cratis/on-behalf`

Describes the current session, re-checking the grant when it is due:

```json
{
  "sessionId": "<opaque session id>",
  "tenant": "<tenant id>",
  "subject": "<represented user's subject>",
  "issue": "<issue id>",
  "startedAt": "2026-09-01T12:00:00+00:00",
  "expiresAt": "2026-09-01T13:00:00+00:00",
  "represented": { "identityProvider": "<idp>", "userId": "<subject>", "userDetails": "<name or email>" }
}
```

It answers `404` with `no-session` when there is none, and `503` with `unavailable` when the grant cannot be
checked.

### While a session is active

- The session acts in the tenant the grant was confirmed for. The tenant selection page is not offered, and a
  tenant from the actor's own claims or selection is replaced. A request whose host, route or fixed
  configuration addresses a **different** tenant is refused with `403`.
- A request whose session has just ended is refused with `403`, carrying the response header
  `x-cratis-on-behalf-ended: <reason>`. It is never forwarded as the actor instead. The next request proceeds as
  the actor.
- A request whose grant cannot be re-checked is refused with `503`. The session is not ended; the next request
  asks again.
- The `.cratis-on-behalf` cookie is HTTP-only, `SameSite=Lax`, host-only, expires with the session and is kept
  apart from the actor's own session cookie. An agent must keep both cookies between requests.

---

## What the application implements

AuthProxy calls three endpoints on the backend of the service named by `OnBehalf:Service`. Each call carries:

| Header | Value |
|---|---|
| `Authorization` | `Bearer <token>`, a signed token described in [Verifying AuthProxy's tokens](#verifying-authproxys-tokens). |
| `x-cratis-tenant-id` | The tenant the session acts in. `Tenant-ID` carries the same value. |
| `x-cratis-on-behalf-actor` | The actor as a client principal: base64 of the [client principal JSON](#the-client-principal-format). |

The calls carry no `x-ms-client-principal`: nobody is signed in as the represented user. Each call times out
after `OnBehalf:Timeout` (10 seconds by default).

### Grant check: `GET /.cratis/on-behalf/grants`

```http
GET /.cratis/on-behalf/grants?subject=<represented subject>&issue=<issue id>&actor=<actor subject>&session=<session id>
```

The query names what is asked. The signed token binds the same facts (`sub`, `issue`, `act`, `sid`, `tenant`);
read them from the token rather than from the query. `session` lets the application refuse a session it has
ended or revoked by identifier.

AuthProxy calls this once before the session starts, and again whenever the remembered answer is older than
`OnBehalf:RecheckInterval`.

**Live.** Answer `200 OK` with:

```json
{
  "live": true,
  "validUntil": "2026-09-01T12:45:00Z",
  "principal": {
    "identityProvider": "<represented user's identity provider>",
    "userId": "<represented subject, exactly as asked>",
    "userDetails": "<name or email>",
    "userRoles": ["<role>"],
    "claims": [{ "typ": "<claim type>", "val": "<claim value>" }]
  }
}
```

- `live` must be the JSON boolean `true`.
- `validUntil` is an ISO 8601 date and time with an offset. AuthProxy never trusts the grant past it.
- `principal` identifies the represented user, in the [client principal format](#the-client-principal-format).
  `userId` must equal the `subject` asked about. This is how AuthProxy obtains the represented user's identity
  without their credentials: it is forwarded as `x-ms-client-principal` for the whole session, so it must carry
  the roles and claims the application authorizes on. AuthProxy adds the `anonymous` and `authenticated` roles
  and drops any claim in the reserved `urn:cratis:bearer:` namespace.

**Not live.** Answer `200 OK` with `{ "live": false }`, or `403` or `404`.

**Anything else** is treated as no answer and is never live: another status, a timeout, a body over 64 KiB, a
`live` that is not a JSON boolean, a missing or unparseable `validUntil`, a missing `principal`, or a `userId`
other than the one asked about. Before the session starts, that refuses the start with `503`. During the session,
it refuses the request with `503` and asks again on the next one.

### Session started: `POST /.cratis/on-behalf/sessions/started`

```json
{
  "sessionId": "<opaque session id>",
  "tenant": "<tenant id>",
  "issue": "<issue id>",
  "subject": "<represented subject>",
  "actor": { "identityProvider": "<idp>", "userId": "<actor subject>", "userDetails": "<name or email>" },
  "startedAt": "2026-09-01T12:00:00+00:00",
  "expiresAt": "2026-09-01T13:00:00+00:00",
  "grantValidUntil": "2026-09-01T12:45:00+00:00"
}
```

Answer with any `2xx` status to acknowledge it. Any other answer, or no answer, means the session is **not**
issued, so a session the application never recorded cannot exist.

### Session ended: `POST /.cratis/on-behalf/sessions/ended`

```json
{
  "sessionId": "<opaque session id>",
  "tenant": "<tenant id>",
  "issue": "<issue id>",
  "subject": "<represented subject>",
  "actor": { "identityProvider": "<idp>", "userId": "<actor subject>", "userDetails": "<name or email>" },
  "startedAt": "2026-09-01T12:00:00+00:00",
  "endedAt": "2026-09-01T12:20:00+00:00",
  "reason": "grant-not-live"
}
```

| `reason` | When |
|---|---|
| `ended-by-actor` | The actor called `POST /.cratis/on-behalf/end`. |
| `grant-not-live` | The grant check answered not live: revoked, or ended by the application. |
| `grant-expired` | The grant's `validUntil` passed. |
| `lifetime-exceeded` | The session reached `OnBehalf:MaximumLifetime`. |
| `actor-session-ended` | The actor signed out, or their own session ended or was terminated. |
| `actor-changed` | Another user signed in on the browser that held the session. |
| `represented-identity-denied` | The application's identity endpoint refused the represented user in the tenant. |

Answer with any `2xx` status. The session has ended whatever you answer, so this notification is not retried.
AuthProxy notifies once per session on each instance. A session ended by revoking the grant can still be noticed
by more than one AuthProxy replica, so record an end idempotently by `sessionId`.

The notification is sent when AuthProxy notices the end. A session that ends because its actor simply stops
making requests is reported at the next request, or never. Treat `expiresAt` from the started notification as
the latest time the session can have lasted.

---

## What the application receives on every request

During an on-behalf session, every forwarded request carries:

| Header | Value |
|---|---|
| `x-ms-client-principal` | The **represented user**, exactly as the grant check identified them, so authorization uses their roles and claims. `x-ms-client-principal-id` and `x-ms-client-principal-name` follow it. |
| `x-cratis-tenant-id` | The session's tenant. `Tenant-ID` carries the same value. |
| `x-cratis-on-behalf-actor` | The **actor**, encoded exactly like `x-ms-client-principal`: base64 of the client principal JSON. |
| `x-cratis-on-behalf-assertion` | A signed token binding the two identity headers, the tenant, the session and the issue. |

Arc records the actor and the represented user as a `CausedBy` chain from these headers (see
[Cratis/Arc#3535](https://github.com/Cratis/Arc/issues/3535)).

Verify `x-cratis-on-behalf-assertion` before believing either identity header, and require its
`principal_hash` and `actor_hash` to match the SHA-256 of the exact header values received. An application that
does not verify it must at least never accept `x-cratis-on-behalf-actor` from anything other than AuthProxy.

AuthProxy removes every inbound header that begins with `x-cratis-on-behalf` or `x-ms-client-principal`, so a
caller can never supply them.

No credential of the actor's is forwarded during a session: the `Authorization` header is removed. A service that
requires a [user access token](services.md#forwarding-the-users-access-token) is refused with `403` during a session, because the only token
AuthProxy holds is the actor's.

When the service has identity resolution configured, AuthProxy calls `/.cratis/me` with the represented user as
the principal and the session's tenant, exactly as for the user's own requests. A refusal there ends the session
with `represented-identity-denied`. The actor's own session is not terminated, even with
`Session:TerminateOnIdentityDenial`.

### The client principal format

```json
{
  "identityProvider": "<provider>",
  "userId": "<subject>",
  "userDetails": "<name or email>",
  "userRoles": ["anonymous", "authenticated", "<role>"],
  "claims": [{ "typ": "<claim type>", "val": "<claim value>" }]
}
```

---

## Verifying AuthProxy's tokens

Every call to the application and every forwarded request carries a short-lived RS256 JWS, signed with
`OnBehalf:Attestation`. It uses the same construction as the [sign-in notification envelope](sign-in.md#the-signed-envelope).

| Claim | Meaning |
|---|---|
| `iss`, `aud` | `OnBehalf:Attestation:Issuer` and `OnBehalf:Attestation:Audience`. |
| `kid` header | The signing key. |
| `iat`, `nbf`, `exp` | Valid for `OnBehalf:Attestation:Lifetime`, 60 seconds by default. |
| `jti` | A random identifier, unique per token. |
| `purpose` | `on-behalf-grant-check`, `on-behalf-session-started`, `on-behalf-session-ended`, or `on-behalf-forward`. |
| `sub` | The represented user's subject. |
| `act` | The actor, as an [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693#name-act-actor-claim) actor claim: `{ "sub": "<actor subject>", "idp": "<actor identity provider>" }`. |
| `tenant` | The tenant the session acts in. |
| `issue` | The issue the grant was given for. |
| `sid` | The on-behalf session identifier. |

A call to the application also carries:

| Claim | Meaning |
|---|---|
| `htm`, `htu` | The method and target of the call, the target without query and fragment ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)). |
| `body_hash` | Unpadded base64url SHA-256 of the exact body. The grant check has no body, so it hashes the empty body. |

A forwarded request (`purpose` `on-behalf-forward`) also carries:

| Claim | Meaning |
|---|---|
| `principal_hash` | Unpadded base64url SHA-256 of the exact `x-ms-client-principal` value. |
| `actor_hash` | Unpadded base64url SHA-256 of the exact `x-cratis-on-behalf-actor` value. |

To verify a token:

1. Select the public key by `kid` from your pinned key set, and require RS256.
2. Validate `iss`, `aud`, `exp` and `nbf`.
3. Require the `purpose` the endpoint expects.
4. For a call, compare `htm` and `htu` with the request, and `body_hash` with the raw body read before
   deserializing. For a forwarded request, compare `principal_hash` and `actor_hash` with the headers.
5. Take `sub`, `act`, `tenant`, `issue` and `sid` from the token, not from the query or body.
6. Reject a `jti` already seen within the token lifetime.

AuthProxy publishes no JWKS document. Pin the public keys in the application's configuration.

---

## Configuration

```json
{
  "Cratis": {
    "AuthProxy": {
      "Services": {
        "portal": { "Backend": { "BaseUrl": "https://portal.internal" } }
      },
      "OnBehalf": {
        "Service": "portal",
        "ActorAuthorization": {
          "RequiredClaims": [ { "Claim": "roles", "AnyOf": [ "support" ] } ]
        },
        "RecheckInterval": "00:00:30",
        "MaximumLifetime": "01:00:00",
        "Timeout": "00:00:10",
        "Attestation": {
          "Issuer": "https://auth.example.com",
          "Audience": "portal",
          "ActiveKeyId": "on-behalf-2026-09",
          "Lifetime": "00:01:00",
          "SigningKeys": [
            { "KeyId": "on-behalf-2026-09", "PrivateKeyPem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----" }
          ]
        }
      }
    }
  }
}
```

| Setting | Default | Meaning |
|---|---|---|
| `Cratis:AuthProxy:OnBehalf` | unset | Enables on-behalf sessions. Unset, the feature does not exist. |
| `OnBehalf:Service` | required | The service whose backend answers the grant check and receives the notifications. It must declare a `Backend` with an absolute HTTPS `BaseUrl` (HTTP only for loopback). |
| `OnBehalf:ActorAuthorization:RequiredClaims` | required | The claims an actor must carry, with the same semantics as [authorization requirements](authorization.md). At least one is required. They apply on top of the deployment's own requirements. |
| `OnBehalf:RecheckInterval` | `00:00:30` | How long a live answer is trusted. Between 1 second and 5 minutes. This is the longest a revoked grant can go on being honored on one instance. |
| `OnBehalf:MaximumLifetime` | `01:00:00` | The longest a session may last, however long the grant is valid. Between 1 minute and 24 hours. |
| `OnBehalf:Timeout` | `00:00:10` | How long AuthProxy waits for each call to the application. Between 1 and 60 seconds. |
| `OnBehalf:Attestation:Issuer` | required | Written to `iss`. |
| `OnBehalf:Attestation:Audience` | required | Written to `aud`. |
| `OnBehalf:Attestation:ActiveKeyId` | required | The key that signs. It must name exactly one configured key. |
| `OnBehalf:Attestation:SigningKeys` | required | Each a `KeyId` and a PEM-encoded RSA `PrivateKeyPem` of at least 2048 bits. Supply the key from a secret store. |
| `OnBehalf:Attestation:Lifetime` | `00:01:00` | Each token's lifetime. Between 10 and 60 seconds. |

Environment variables use the `Cratis__AuthProxy__OnBehalf__` prefix, for example
`Cratis__AuthProxy__OnBehalf__Service=portal`.

AuthProxy validates the section at startup and refuses to start with an unknown service, no actor requirement,
missing or unusable signing keys, or a value outside its range.

To rotate a key, add the new key to `SigningKeys`, publish its public half to the application, then move
`ActiveKeyId` to it. Keep the previous key until every token it signed has expired.

---

## Security notes

- **The application decides.** AuthProxy never issues a session without a live grant and an acknowledged start,
  and never continues one past an answer that is not live. Every failure goes toward the actor not acting as
  anybody: an unreachable application refuses requests rather than forwarding them as either identity.
- **Revocation is bounded by the re-check interval.** A revoked grant is honored for at most
  `OnBehalf:RecheckInterval` after the last live answer, per AuthProxy instance. The grant check receives the
  session identifier, so the application can also end one session without revoking the grant.
- **Two gates for the actor.** The actor must pass the deployment's normal authorization as themselves, and
  `OnBehalf:ActorAuthorization`. Keep this narrow: it decides who may ask the application for a grant at all.
- **The cookie is worth nothing alone.** It holds the protected session record, sealed with the deployment's
  [data protection keys](data-protection.md), and never any credential or the represented user's details.
  A request whose signed-in caller is not the actor it names ends the session instead of using it. A copied
  cookie of an ended session is refused on the instance that ended it, and by the grant check everywhere else.
- **No credentials cross.** The represented user's sign-in is never used. The actor's own credentials are never
  forwarded during a session, so the application never sees one identity's credential on a request attributed to
  the other.
- **Cross-site starts are refused.** Starting a session needs a JSON body, which a cross-site form cannot send
  without a CORS preflight that AuthProxy never answers.
- **Both identities are signed.** The assertion binds the exact identity header values, the tenant, the session
  and the issue. Verify it, and keep the application's backend reachable only through AuthProxy.
- **The tenant is fixed.** A session never moves into a tenant other than the one its grant was confirmed for.
- **Personal data.** The notifications carry the actor's and the represented user's identifiers. Handle and retain
  them in the application accordingly.
