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

AuthProxy posts the following JSON to the configured [`NotifyUrl`](#configuration):

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

- **`subject`** / **`identityProvider`** — read from the freshly authenticated principal, exactly as the invite
  and link exchanges do.
- **`ipAddress`** — the client IP, taken from the left-most `X-Forwarded-For` entry (falling back to the
  connection's remote address).
- **`location`** — a best-effort, coarse location. See [Approximate location](#approximate-location) below.
- **`browser`** / **`operatingSystem`** — parsed from the `User-Agent` header with a lightweight built-in
  heuristic (no third-party user-agent database). Unrecognized values are sent as empty strings rather than
  guessed.
- **`userAgent`** — the raw header, so the application can do its own richer parsing if it wants to.

Unlike the invite and link exchanges, the sign-in notification carries **no bearer token** — there is no
user-supplied token in this flow. It relies on the endpoint being network-isolated (see [Security](#security)).

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

## Security

The notification endpoint is a service-to-service back-channel: it is reachable by AuthProxy, not by browsers.
It trusts the subject AuthProxy delivers from a real provider authentication — never a client-supplied subject.
Point `NotifyUrl` at an internal application address that is **network-isolated** from public traffic, exactly
as for the invite and link exchanges.
