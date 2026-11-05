---
title: "AuthProxy sign-in callbacks for service activity"
description: "Configure per-service AuthProxy callbacks for sign-ins and returning users, with best-effort delivery, identity headers, and receiver trust checks."
---

<a id="sign-in-callback"></a>

Cratis AuthProxy can notify a service's backend when a user signs in or returns with an existing browser session.
Configure a per-service `SignInCallback` to update activity records or start per-user work without detecting
returning users in every application. Delivery runs in the background, so the browser request does not wait for it.

A service without a `SignInCallback` section receives no callbacks. If you need one application endpoint to record
completed sign-ins with the client's location and browser, use the proxy-wide [sign-in notification](./sign-in.md).
That notification is awaited during sign-in; service callbacks run independently in the background.

---

## Configuration

Add `SignInCallback` to a service that declares a `Backend`. AuthProxy appends `Path` to that backend's `BaseUrl`:

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

A frontend-only service cannot receive a callback. `Path` must start with a single `/` and cannot contain a host,
query, fragment, backslash, whitespace, or control character. It selects a path on the declared backend, not an
independent destination. `Interval` must be greater than zero, and `Secret` cannot contain control characters.
Invalid callback configuration stops AuthProxy at startup with a message that names the setting.

---

## When it fires

| Kind | When |
|---|---|
| `SignedIn` | Queued when a primary identity-provider sign-in completes for the service, however recently the user signed in before. |
| `Returned` | On the first request a user's existing session makes to the service, and then at most once per `Interval` for that user and service. |

Only a browser cookie session produces a `Returned` callback. Bearer-token and machine-to-machine requests,
on-behalf sessions, unauthenticated requests, and requests AuthProxy refuses do not count as returns. A sign-in
resets the interval, so the request that follows a `SignedIn` is not also reported as `Returned`.

The interval starts at the last `SignedIn` or `Returned` notification attempt. Requests within that interval do
not restart it. AuthProxy tracks each user separately for each service, so visiting one service does not suppress
callbacks to another.

AuthProxy attributes the sign-in to the service matched by the provider callback request under the normal
[service-routing rules](./services.md). If a shared [callback host](./sign-in.md#running-the-handshake-on-one-host)
does not resolve to a service, no `SignedIn` is queued; the user's first proxied request to a service with a
callback reports `Returned` instead.

---

## The call

AuthProxy sends one `POST` to `{Backend.BaseUrl}{Path}`.

### Headers

| Header | Value |
|---|---|
| `x-cratis-sign-in-callback` | The kind: `SignedIn` or `Returned`. Identifies a callback but is not a credential. |
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

The callback marker identifies the callback kind; it does not authenticate the sender. AuthProxy strips every
inbound header that starts with `x-cratis-sign-in-callback`, including the secret header, before forwarding a
client request. That prevents a caller from supplying those headers through the proxy, but it does not protect
a backend that accepts direct requests.

Restrict backend access to the proxy, as you would when trusting ordinary identity headers. If other callers can
reach the backend directly, configure `Secret` through a secret store or environment variable. Have the receiver
reject a missing or incorrect `x-cratis-sign-in-callback-secret` before acting, using a constant-time comparison.
Without a secret, the receiver relies on network isolation alone. Keep the secret out of committed files and
protect the connection that carries it.

---

## Delivery guarantees

Delivery is best-effort, not at-least-once. AuthProxy queues callbacks in memory and sends them from background
workers with the configured timeout. A failed, timed-out, or non-successful attempt is logged without retry.
When the bounded queue is full, AuthProxy logs and drops the new callback. A restart loses queued callbacks.
Callback failures do not block or fail the user's sign-in or proxied request.

The receiver must also tolerate duplicates. AuthProxy remembers users in memory on each replica, and that state
is lost on restart. With several replicas, or after a restart, a service can receive the same `Returned` more
than once within an interval. Make the receiver idempotent: processing a duplicate must not repeat a side effect
that should happen only once.

A callback may arrive after the user's request reaches the backend, or never arrive at all. Do not make serving
that request depend on callback delivery. A failed or dropped callback does not reset the interval, so the next
request does not trigger an immediate retry.

Use the callback logs to investigate delivery: they report failures, timeouts, refused responses, and full-queue
drops without including the configured secret or identity payload. There is no persistent delivery store or
callback-specific metrics surface.
