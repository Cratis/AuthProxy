---
title: "Sign-in Callback"
description: "Have AuthProxy tell an application, server to server, when a user signs in and when a returning user's session makes its first request."
---

# Sign-in Callback

A service can ask AuthProxy to call it back when a user signs in, and again when a user comes back with a session
that already exists. The application learns who is active ("last seen") and can run first-request work without
detecting a first request itself.

It is **off by default**. A service that declares no `SignInCallback` is never called.

This is not the same as the [sign-in notification](./sign-in.md). The notification is one proxy-wide endpoint that
reports a sign-in together with the client's location and browser. The sign-in callback is declared **per service**,
presents the user the way every proxied request does, and also reports returns.

---

## Configuration

Declare the callback on the service it is for:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Services": {
        "core": {
          "Backend": { "BaseUrl": "http://core:8080/" },
          "SignInCallback": {
            "Path": "/.cratis/showrunner/sign-in",
            "Interval": "12:00:00",
            "Timeout": "00:00:05",
            "Secret": ""
          }
        }
      }
    }
  }
}
```

| Setting | Default | Meaning |
|---|---|---|
| `Path` | — (required) | The absolute path on the service's `Backend` that receives the call. It must start with a single `/` and carry no host, query or fragment. |
| `Interval` | `12:00:00` | The least time between two `Returned` callbacks for the same user and service. |
| `Timeout` | `00:00:05` | How long AuthProxy waits for the service to answer. Must be above zero and at most one minute. |
| `Secret` | empty | A shared secret sent in a header, so the service can tell AuthProxy from any other caller on its network. Supply it from a secret store or the environment, never from a committed file. |

The service must declare a `Backend`: the call goes to the same internal address AuthProxy proxies requests to.
A configuration that cannot work — a missing path, a relative path, a non-positive interval or timeout, or no
backend — stops AuthProxy at startup with a message that names the setting.

---

## When it fires

| Kind | When |
|---|---|
| `SignedIn` | Right after an identity-provider callback succeeds and a fresh session is established. Always sent, however recently the user signed in before. |
| `Returned` | On the first request a user's existing session makes to the service, and then at most once per `Interval` for that user and service. |

A `Returned` callback is not sent for a request that is not a browser session (a bearer token, a machine
client), for an on-behalf session, for an unauthenticated request, or for a request AuthProxy refuses. A sign-in
resets the interval, so the request that follows a `SignedIn` is not also reported as `Returned`.

The sign-in is attributed to the service the provider callback request resolves to (by host, then by the single or
default service). When the callback runs on a shared [callback host](./sign-in.md#running-the-handshake-on-one-host) that does not resolve to a
service, no `SignedIn` is sent; the user's first proxied request reports `Returned` instead.

---

## The call

AuthProxy sends one `POST` to `{Backend.BaseUrl}{Path}`.

### Headers

| Header | Value |
|---|---|
| `x-cratis-sign-in-callback` | The kind: `SignedIn` or `Returned`. Marks the call as AuthProxy's own. |
| `x-cratis-sign-in-callback-secret` | The configured `Secret`. Sent only when one is configured. |
| `x-ms-client-principal`, `x-ms-client-principal-id`, `x-ms-client-principal-name` | The user, exactly as on a proxied request. |
| `x-cratis-tenant-id`, `Tenant-ID` | The resolved tenant. Sent only when a tenant resolved. |
| `x-cratis-microservice`, `Service-ID` | The configured name of the service. |
| `Content-Type` | `application/json` |

### Body

```json
{
  "kind": "SignedIn",
  "subject": "134365",
  "name": "Ada Lovelace",
  "email": "ada@example.com",
  "identityProvider": "github",
  "tenant": "acme",
  "occurred": "2026-11-03T09:00:00+00:00"
}
```

`kind`, `subject`, `name`, `email`, `identityProvider` and `occurred` are always present; `name` and `email` are
empty strings when the provider gave none. `tenant` is **omitted** when no tenant resolved. `subject` is the same
value as `x-ms-client-principal-id`. Any `2xx` answer counts as accepted; the response body is ignored.

---

## Trust

The callback arrives from AuthProxy over the internal network, the same way proxied requests do. Two things let the
receiver rely on it:

- **The marker headers cannot be forged through the proxy.** AuthProxy strips every inbound header that starts with
  `x-cratis-sign-in-callback`, so a browser that posts to the callback path through the proxy cannot present the
  marker or the secret.
- **The secret covers the network.** Anything that can reach the service directly could still send the marker.
  Configure a `Secret` and have the service reject a call whose `x-cratis-sign-in-callback-secret` does not match, compared
  in constant time. Without a secret the service relies on network isolation alone.

---

## Delivery guarantees

- **It never blocks or fails the user's request.** The callback is queued and sent from a background worker with the
  configured timeout. A failure is logged — never with the secret or the user's identity — and the request carries on.
- **It is at-least-once on a best-effort basis, and can be missed.** The queue is in memory and bounded. When a service
  stops answering and the queue fills, new callbacks are dropped and logged. A restart loses what was queued.
- **The receiver must be idempotent.** What AuthProxy remembers per user and service is held in memory, per replica,
  and is lost on restart. With several replicas, or after a restart, a service can receive the same `Returned` more than
  once within an interval.

No new database is involved, and there are no metrics for it beyond the log.
