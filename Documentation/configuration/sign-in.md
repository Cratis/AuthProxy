# Sign-in Notifications

AuthProxy can notify the application every time a user **actually signs in** — that is, when a signed-out
user completes an interactive identity-provider login and a fresh session is established. The application can
then record the sign-in, for example to alert the user of a new sign-in from an unfamiliar location or device.

The notification is a service-to-service back-channel, mirroring the [invite exchange](./lobby/invitation-to-organization.md)
and the [credential link callback](./link.md): AuthProxy `POST`s a small JSON payload to a configured
application endpoint.

---

## When it fires

The notification fires **only on a genuine logged-out → signed-in transition**:

- ✅ A signed-out user is redirected to an identity provider, authenticates, and returns with a fresh ticket.
- ❌ An already-authenticated user making ordinary proxied requests — the existing session cookie is reused,
  no provider round-trip happens, and no notification is sent.
- ❌ The [credential-linking](./link.md) flow — that authenticates a *second* provider without establishing a
  new primary session, so it is never reported as a sign-in.

Technically, AuthProxy hooks the provider **callback** (`OnTicketReceived`), which the framework raises only
when a new authentication ticket is delivered from a provider — not when an existing session is validated.
That is what scopes the event to real sign-ins rather than every request. A notification failure never breaks
the sign-in: the call is best-effort and any error is logged and swallowed.

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

- **Identity fields** — legacy providers select `subject` and `identityProvider` from the freshly
  authenticated principal. Canonical providers send the complete `(providerKey, issuer, subject)` tuple.
  Consumers must bind all three tuple components; neither `subject` alone nor `identityProvider` is a stable
  cross-provider account key.
- **`ipAddress`** — the client IP, taken from the left-most `X-Forwarded-For` entry (falling back to the
  connection's remote address).
- **`location`** — a best-effort, coarse location. See [Approximate location](#approximate-location) below.
- **`browser`** / **`operatingSystem`** — parsed from the `User-Agent` header with a lightweight built-in
  heuristic (no third-party user-agent database). Unrecognized values are sent as empty strings rather than
  guessed.
- **`userAgent`** — the raw header, so the application can do its own richer parsing if it wants to.

By default the notification carries **no credential** and relies on the endpoint being network-isolated (see
[Security](#security)). Configure [the signed envelope](#the-signed-envelope) to authenticate it instead.

Canonical identity is opt-in per provider, so an application migrating provider registrations must accept
both body shapes. A notification says that a provider authenticated the tuple; it does not grant application
membership, roles, scopes, or authorization.

---

## Approximate location

AuthProxy deliberately does **not** bundle a geo-IP database — that would be a heavy dependency and a data
pipeline of its own. The `location` is instead derived from what is already on the request:

- the resolved client IP (always sent); and
- coarse geo headers that a fronting CDN or reverse proxy may add — Cloudflare's `CF-IPCountry`, and the
  conventional `X-Geo-City` / `X-Geo-Region` / `X-Geo-Country` and `X-AppEngine-City` / `-Region` / `-Country`
  headers.

When those headers are present, `location` is assembled as `City, Region, Country`. When they are **not**
present, `location` is empty and only the IP travels — the application can resolve a fuller location from the
IP itself if it needs one. This keeps AuthProxy dependency-light while still recording a genuine approximate
location wherever the infrastructure provides one.

> **Note.** The client IP and any derived location are personal data. Handle and retain them in the application
> accordingly.

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

```
Cratis__AuthProxy__SignIn__NotifyUrl=https://studio.example.com/api/internal/sign-ins
```

When `NotifyUrl` is empty or the `SignIn` section is absent, sign-in notifications are disabled (nothing is
posted).

---

## The signed envelope

Without further configuration the notification body is the *only* evidence the application has, so anything
that can reach the endpoint chooses which user gets recorded as signed in — including the `subject`,
`providerKey` and `issuer`. Set `Cratis:AuthProxy:SignIn:Attestation` and AuthProxy signs a short-lived RS256
JWS over each notification and sends it as `Authorization: Bearer`.

**The body is unchanged.** The envelope travels in a header, so an application already consuming
notifications keeps parsing exactly the same JSON.

### What the envelope binds

The envelope is a profile of [RFC 9449 (DPoP)](https://www.rfc-editor.org/rfc/rfc9449) rather than a scheme of
its own. Six facts are bound:

| Fact | Carried by | Meaning |
|---|---|---|
| Provenance | `iss` + the `kid` JWS header | which AuthProxy deployment signed it, and under which key |
| Audience | `aud` | the single application entitled to consume it |
| Route | `htm`, `htu` | the method and target URI of the request it accompanies |
| Body | `body_hash` | base64url SHA-256 of the exact bytes posted |
| Time | `iat`, `nbf`, `exp` | the window it is valid in |
| Replay | `jti` | a random 256-bit identifier, unique per notification |

A `purpose` claim of `sign-in-notification` separates the envelope from every other assertion AuthProxy signs,
so an invitation attestation can never be presented in its place.

Two details a verifier must implement exactly:

- **`htu` follows RFC 9449** — the target URI *without* query and fragment. Compare it against the
  query-stripped request URI, not the raw target.
- **`body_hash` is an AuthProxy extension** — RFC 9449 defines no body digest. It uses the identical
  construction to that specification's `ath` claim: unpadded base64url of the SHA-256 of the raw request body.

### Verifying a notification

1. Reject the request outright if the `Authorization: Bearer` header is missing.
2. Select the public key by the JWS `kid` header from your pinned key set, and require RS256.
3. Validate `iss`, `aud`, `exp` and `nbf` with no clock skew allowance beyond your own tolerance.
4. Require `purpose` to be `sign-in-notification`.
5. Compare `htm` to the request method and `htu` to the request URI with query and fragment removed.
6. Read the raw request body **before** deserializing it, and compare `body_hash` to its SHA-256 digest.
7. Reject a `jti` already seen inside the envelope lifetime.

> **AuthProxy publishes no JWKS document.** The verifying application pins the public keys by its own
> configuration and selects one by `kid` — the same way the invitation authority consumes invitation
> attestations. Key rotation is therefore a coordinated configuration change on both sides.

### Configuring it

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
| `Cratis:AuthProxy:SignIn:Attestation:SigningKeys` | the available keys, each a `KeyId` and a PEM-encoded RSA `PrivateKeyPem` of at least 2048 bits |
| `Cratis:AuthProxy:SignIn:Attestation:Lifetime` | the envelope lifetime; between 10 and 60 seconds, defaulting to 60 |

Supply `PrivateKeyPem` through a secret provider. AuthProxy never returns or logs it — publish only the
matching public key to the application.

**Key rotation.** Add the new key to `SigningKeys`, publish its public half to the application, then move
`ActiveKeyId` to it. Keep the previous key configured until every envelope it signed has expired.

### Compatibility and failure behavior

- **Leaving the section unset changes nothing.** No `Authorization` header is added and the body is byte-for-byte
  what it has always been.
- **Once configured, AuthProxy never downgrades.** If an envelope cannot be signed — unusable key material,
  an `ActiveKeyId` naming no key — the notification is *not posted at all* and the failure is logged. A
  sign-in is never recorded on unauthenticated evidence.
- **Configuration is validated at startup**, so an unusable key fails the process rather than silently
  suppressing every sign-in notification. When attestation is configured, `NotifyUrl` must also be an absolute
  HTTPS URL (HTTP is accepted only for loopback development).

---

## Security

**Unsigned by default.** With no [`Attestation`](#the-signed-envelope) section the notification JSON is not
signed and carries no credential. Point `NotifyUrl` at an internal application address that is
**network-isolated** from public traffic, or authenticate AuthProxy separately at the application endpoint.

**Signed when configured.** The envelope establishes that AuthProxy produced this exact notification, for this
application, over this exact body, recently, and only once. Network isolation and an authenticated envelope
are complementary — enabling one is not a reason to relax the other.

Either way, treat the identity tuple as authenticated provider metadata, then apply the application's own
authorization policy before changing any access or membership. A verified envelope proves the notification's
origin and integrity; it grants no membership, role, or scope.
