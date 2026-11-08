---
title: "AuthProxy sign-in notifications and receiver verification"
description: "Configure AuthProxy to report completed sign-ins to your application, including client metadata, delivery behavior, and signed-notification verification."
---

<a id="sign-in-notifications"></a>

Cratis AuthProxy can post completed primary sign-ins to an application endpoint so your application can record
sign-in activity or alert users to an unfamiliar location or device. Configure `SignIn.NotifyUrl` to receive
identity details, the client's IP address, and browser metadata over a server-to-server connection.

Like the [invite exchange](./lobby/invitation-to-organization.md) and [credential link callback](./link.md),
this connection carries a JSON payload from AuthProxy to your application. The receiver decides what to record
or act on. To notify individual services about sign-ins and returning users instead, use the per-service
[sign-in callback](./sign-in-callback.md).

---

## When it fires

AuthProxy sends the notification when it accepts a new primary authentication ticket from an identity provider
in `OnTicketReceived`. For example, a signed-out user follows a login redirect, authenticates, and returns with
a fresh ticket. Ordinary proxied requests that reuse a session cookie do not send notifications.

The [credential-linking](./link.md) flow authenticates a second provider without establishing a new primary
session, so it does not send a sign-in notification.

AuthProxy awaits the notification request during sign-in. A slow receiver can therefore delay completion, unlike
the background per-service callback. A failed request or non-success response is logged without preventing the
sign-in, and AuthProxy does not retry it. Treat this as a best-effort activity signal, not a complete sign-in ledger.

---

## The payload

AuthProxy posts one of two JSON bodies to the configured [`NotifyUrl`](#configuration). A provider without
[canonical federated identity](authentication.md#canonical-federated-identity) keeps the legacy body:

```json
{
  "subject": "<provider subject>",
  "identityProvider": "<issuer / provider>",
  "ipAddress": "<resolved client IP>",
  "location": "<approximate location, may be empty>",
  "browser": "<parsed browser, e.g. Chrome>",
  "operatingSystem": "<parsed OS, e.g. Windows>",
  "userAgent": "<raw User-Agent header>"
}
```

An opted-in canonical provider adds `providerKey` and `issuer`; `subject` is the exact configured canonical
subject and `identityProvider` becomes the same compatibility value as `providerKey`:

```json
{
  "subject": "<configured canonical subject>",
  "providerKey": "<configured stable provider key>",
  "issuer": "<normalized validated or configured issuer>",
  "identityProvider": "<same value as providerKey>",
  "ipAddress": "<resolved client IP>",
  "location": "<approximate location, may be empty>",
  "browser": "<parsed browser, e.g. Chrome>",
  "operatingSystem": "<parsed OS, e.g. Windows>",
  "userAgent": "<raw User-Agent header>"
}
```

For legacy providers, AuthProxy reads `subject` from the freshly authenticated principal and uses the challenged
provider's name for `identityProvider` when available, falling back to identity claims. Canonical providers send
the complete `(providerKey, issuer, subject)` tuple. Bind all three components when identifying an account;
neither `subject` alone nor `identityProvider` is a stable cross-provider account key.

The remaining fields describe the request:

| Field | Meaning |
|---|---|
| `ipAddress` | The connection's remote IP after AuthProxy's trusted forwarded-header processing. AuthProxy does not read `X-Forwarded-For` directly for this field. |
| `location` | A coarse location from trusted proxy headers. See [Approximate location](#approximate-location). |
| `browser`, `operatingSystem` | Parsed from `User-Agent` by built-in heuristics, without a third-party database. Unrecognized values are empty strings. |
| `userAgent` | The raw `User-Agent` header, available for application-side parsing. |

These request details provide context, not proof of a person's location or device identity. By default the
notification carries no credential and relies on endpoint isolation or separate authentication (see
[Security](#security)). Configure [the signed envelope](#the-signed-envelope) to let the receiver verify AuthProxy
as the sender and check the notification's integrity.

Canonical identity is opt-in per provider, so an application migrating provider registrations must accept
both body shapes. A notification says that a provider authenticated the tuple; it does not grant application
membership, roles, scopes, or authorization.

---

## Approximate location

AuthProxy does not perform geo-IP lookups. It reads location headers only when the request comes from a trusted
proxy. Supported headers include Cloudflare's `CF-IPCity`, `CF-Region`, and `CF-IPCountry`, as well as
`X-Geo-City` / `X-Geo-Region` / `X-Geo-Country` and `X-AppEngine-City` / `-Region` / `-Country`.

Available values are joined in city, region, country order. If no supported headers are present, or the request
did not come from a trusted proxy, `location` is empty. The resolved IP still travels in `ipAddress`, and the
application can use it for its own lookup if needed. Configure the fronting proxy to replace caller-supplied
location headers before relying on them.

The client IP and any derived location are personal data. Choose how the application stores them and how long
it retains them.

---

## Configuration

Set the application endpoint that records a completed sign-in under `Cratis:AuthProxy:SignIn:NotifyUrl`.

```json
{
  "Cratis": {
    "AuthProxy": {
      "SignIn": {
        "NotifyUrl": "https://studio.example.com/api/internal/sign-ins"
      }
    }
  }
}
```

Equivalent environment variable:

```dotenv
Cratis__AuthProxy__SignIn__NotifyUrl=https://studio.example.com/api/internal/sign-ins
```

When `NotifyUrl` is empty or the `SignIn` section is absent, sign-in notifications are disabled (nothing is
posted).

### Running the handshake on one host

If your deployment serves several hosts, `SignIn.CallbackHost` lets their identity-provider login exchanges run
on one host. You can then register a single callback and a single post-logout address with the provider.
This setting controls the browser login flow, not the notification destination:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Session": { "CookieDomain": ".example.com" },
      "SignIn": { "CallbackHost": "auth.example.com" }
    }
  }
}
```

| Property | Default | Description |
|----------|---------|-------------|
| `CallbackHost` | `""` | Host, with an optional port, for primary sign-in and sign-out handshakes. When empty, each host completes its own. It requires `Session:CookieDomain`, and the host must lie inside that domain; AuthProxy refuses to start otherwise. |

A sign-in or sign-out that starts on another host is sent to the callback host and returns to the original
address, which is only honored for hosts a service declares, frontends, the lobby and
[`Logout:AllowedRedirectOrigins`](logout.md#allowing-additional-post-logout-origins), inside the cookie domain.
Invitations, credential links and registration keep running on the host they start on. See
[One proxy, several hosts](one-proxy-several-hosts.md#4-run-every-handshake-on-one-host).

---

## The signed envelope

An unsigned body does not prove who sent it. Without endpoint isolation or separate authentication, anyone who
can reach the receiver can choose the `subject`, `providerKey`, and `issuer` it records. Configure
`Cratis:AuthProxy:SignIn:Attestation` to have AuthProxy send a signed envelope with each notification.

The envelope is a short-lived JSON Web Signature (JWS), signed with RSA and SHA-256 using the RS256 algorithm.
It travels in `Authorization: Bearer`; the JSON body stays unchanged. The receiver must verify the envelope
before acting on the body.

### What the envelope binds

The envelope uses the method and URI claims defined by [RFC 9449 (DPoP)](https://www.rfc-editor.org/rfc/rfc9449),
which binds a proof to an HTTP request. AuthProxy adds a body digest. The receiver checks the following bindings:

| Fact | Carried by | Meaning |
|---|---|---|
| Provenance | `iss` + the `kid` JWS header | which AuthProxy deployment signed it, and under which key |
| Audience | `aud` | the single application entitled to consume it |
| Route | `htm`, `htu` | the method and target URI of the request it accompanies |
| Body | `body_hash` | base64url SHA-256 of the exact bytes posted |
| Time | `iat`, `nbf`, `exp` | the window it is valid in |
| Replay | `jti` | a random 256-bit identifier the receiver uses to detect reuse |

Require `purpose` to be `sign-in-notification` so the receiver rejects other assertions, such as invitation
attestations, even if they use the same signing keys.

The `htu` claim follows RFC 9449: it contains the target URI without query or fragment. Compare it against the
request URI with those parts removed. With `Attestation` configured, AuthProxy rejects a `NotifyUrl` containing
a query because that query would not be covered by the signature.

The `body_hash` claim is an AuthProxy extension because RFC 9449 defines no body digest. It uses the same
construction as that specification's `ath` claim: unpadded base64url of the SHA-256 of the raw request body.

### Verifying a notification

1. Reject the request outright if the `Authorization: Bearer` header is missing.
2. Select the public key by the JWS `kid` header from your pinned key set, and require RS256.
3. Require the configured `iss` and `aud`, and validate `iat`, `nbf`, and `exp` against your accepted validity window and clock-skew tolerance.
4. Require `purpose` to be `sign-in-notification`.
5. Compare `htm` to the request method and `htu` to the request URI with query and fragment removed.
6. Read the raw request body before deserializing it. Compute its SHA-256 digest, encode it as unpadded base64url, and compare it to `body_hash`.
7. Require `jti` and atomically record it before processing the notification. Reject a value already seen, and retain it through the accepted validity window. Receivers with multiple replicas need shared replay tracking.

AuthProxy publishes no JSON Web Key Set (JWKS) document for key discovery. Configure the receiver's trusted
public keys explicitly and select one by `kid`, as for invitation attestations. Key rotation requires coordinated
configuration changes on both sides.

### Configuring it

Configure the signing identity, audience, and active key. The PEM value below is a placeholder, not usable key
material.

```json
{
  "Cratis": {
    "AuthProxy": {
      "SignIn": {
        "NotifyUrl": "https://studio.example.com/api/internal/sign-ins",
        "Attestation": {
          "Issuer": "https://auth.example.com",
          "Audience": "studio",
          "ActiveKeyId": "sign-in-2026-08",
          "Lifetime": "00:00:60",
          "SigningKeys": [
            {
              "KeyId": "sign-in-2026-08",
              "PrivateKeyPem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
            }
          ]
        }
      }
    }
  }
}
```

| Setting | Meaning |
|---|---|
| `Cratis:AuthProxy:SignIn:Attestation:Issuer` | written to `iss`; required, and required to match at the verifier |
| `Cratis:AuthProxy:SignIn:Attestation:Audience` | written to `aud`; names the one application entitled to the notification |
| `Cratis:AuthProxy:SignIn:Attestation:ActiveKeyId` | the key new envelopes are signed with; must name exactly one configured key |
| `Cratis:AuthProxy:SignIn:Attestation:SigningKeys` | the available keys, each a `KeyId` and a PEM-encoded RSA `PrivateKeyPem` of at least 2048 bits; every `KeyId` must be unique |
| `Cratis:AuthProxy:SignIn:Attestation:Lifetime` | the envelope lifetime; between 10 and 60 seconds, defaulting to 60 |
| `Cratis:AuthProxy:SignIn:IncludeVerifiedUpstreamClaims` | `false` by default; when `true`, adds [verified upstream claims](#verified-upstream-claims) to the signed body and requires `Attestation` |

Supply `PrivateKeyPem` through a secret provider. AuthProxy never returns or logs it — publish only the
matching public key to the application.

To rotate keys, add the new key to `SigningKeys` and configure its public half in the application before moving
`ActiveKeyId` to it. Keep the previous public key available to the receiver until every envelope it signed is
outside the receiver's accepted validity window.

### Verified upstream claims

By default the notification names the account but carries nothing the identity provider itself asserted. Set
`Cratis:AuthProxy:SignIn:IncludeVerifiedUpstreamClaims` to `true` to add a `verifiedClaims` object to the signed
body. It requires `Attestation`: the claims are only ever sent inside a signed body, so the host refuses to start
without it.

```json
{
  "subject": "...",
  "verifiedClaims": {
    "iss": "<issuer of the identity token>",
    "sub": "<account id>",
    "idp": "<identity provider>",
    "idp_sub": "<subject at the identity provider>",
    "github_id": "<external account id>",
    "auth_time": 1700000000,
    "jti": "<token id>"
  }
}
```

What a receiver can trust:

- Every value was read by AuthProxy from the identity token it validated for this sign-in (signature, issuer,
  audience, lifetime, state and PKCE). None comes from the user-info response, the session, a request header or
  anything the caller sent, and a caller-supplied copy is never forwarded.
- A claim the token does not carry, carries more than once, or carries malformed (`auth_time` must be whole
  seconds) is left out. Absence means "not verified", never a default.
- The claims are inside the body covered by `body_hash`, so changing one invalidates the envelope. Verify the
  envelope first, and trust `verifiedClaims` only from a verified envelope.
- No token is carried, stored or logged; only these claims are.
- Only OpenID Connect providers contribute claims. A sign-in through an OAuth-only provider sends no
  `verifiedClaims`.
- The object is a statement about the provider's authentication. It grants no membership, role or scope.

Without the setting the notification is unchanged.

### Compatibility and failure behavior

Without an `Attestation` section, AuthProxy adds no `Authorization` header and sends the same JSON body. Once
signing is configured, an unusable key or missing active key causes AuthProxy to log the failure and skip the
notification. It does not fall back to an unsigned request. The user's sign-in still proceeds.

AuthProxy validates signing configuration at startup, including key material and the active key identifier.
When attestation is configured, `NotifyUrl` must be an absolute HTTPS URL without credentials, a query, or a
fragment. HTTP is accepted only for loopback development.

---

## Security

With no [`Attestation`](#the-signed-envelope) section, the notification carries no credential. Point `NotifyUrl`
at an internal endpoint isolated from public traffic, or authenticate AuthProxy separately at the receiver.
Do not treat a request body as trusted merely because it names a provider and subject.

A verified envelope establishes the notification's origin and integrity for the configured application and
validity window. Preventing replay also requires the receiver to reject reused `jti` values; a valid signature
alone does not make a notification single-use. Keep network isolation in place when enabling signatures.

After authenticating the notification, apply the application's authorization policy before changing access or
membership. The identity tuple describes the provider-authenticated account; it grants no membership, role,
or scope. If your next task is tracking activity when an existing session returns to a service, configure the
[per-service sign-in callback](./sign-in-callback.md) rather than adding that work to this receiver.
