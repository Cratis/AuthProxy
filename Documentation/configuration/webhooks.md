# Receiving Webhooks

An inbound webhook is a request from a system that has no user session and never will. AuthProxy has two
mechanisms for it, and which one applies depends on a single question: **do you control the sender?**

---

## Choosing the mechanism

| The sender is | Use | Why |
|---|---|---|
| A service or application you control | [Client credentials](authentication.md#back-channel-client-credentials) | The sender can exchange credentials at `/.cratis/token` for a bearer token scoped to a route prefix. The proxy authenticates it, and the application receives a caller it can trust. |
| A third party — Stripe, GitHub, Slack, an e-sign provider | [`AnonymousPaths`](services.md#anonymous-paths) | They will not perform a token exchange. They sign the request their own way, and only the application knows how to check it. |

If you control the sender, prefer client credentials. It keeps authentication in the proxy, which is what
the proxy is for. Reach for `AnonymousPaths` when the sender's scheme is not yours to choose.

---

## Third-party webhooks

Declare the specific path the provider posts to:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Services": {
        "core": {
          "Backend": { "BaseUrl": "http://core:8080/" },
          "AnonymousPaths": [ "/api/webhooks/payments" ]
        }
      }
    }
  }
}
```

### What AuthProxy does

- Forwards the request to the service instead of answering it with a sign-in page.
- Strips inbound `x-ms-client-principal`, `x-ms-client-principal-id`, `x-ms-client-principal-name` and
  `Tenant-ID` headers, exactly as it does for every other request. A caller cannot assert an identity.
- Injects no principal headers, because there is no session.

### What AuthProxy does not do

**It does not authenticate the request.** A declared path is reachable by anyone who knows the URL. The
signature check is the application's, and it is not optional — without it the endpoint accepts anything
that anyone posts to it.

A typical provider signs a request with an HMAC over the raw body plus a timestamp. Verifying it means:

1. Reading the **raw body bytes**, before any deserialization.
2. Recomputing the signature with the shared secret, following that provider's exact canonical form.
3. Comparing in **constant time**.
4. Rejecting timestamps outside a short window, so a captured request cannot be replayed.

### Why the proxy does not do this for you

Not an omission — a deliberate boundary:

- **Every provider canonicalizes differently.** Stripe signs `timestamp.body`, GitHub signs the body
  alone, Slack signs `v0:timestamp:body`, and they disagree on hex versus base64 and on tolerance windows.
  Configuring that generically is harder to get right than implementing it once in the application.
- **It requires buffering the body.** AuthProxy streams request bodies. Buffering them to compute a
  signature changes the memory profile of the path and risks altering exactly the bytes being verified.
- **The application needs the raw body regardless**, for idempotency and for storing the event, so it is
  already holding the thing that has to be checked.

---

## Keeping the opening small

- **Name the exact path.** Entries are prefixes and cover everything beneath them, so `/api/webhooks`
  opens every current and future webhook route, including ones added later by someone who did not know the
  prefix was public. `/api/webhooks/payments` opens one.
- **Reject the methods you do not serve.** A webhook receiver is almost always `POST` only.
- **Treat the payload as untrusted until verified**, including any identifiers used to look up records.
- **Re-read the declared paths when reviewing the deployment.** They are the surface reachable without a
  session, and they are the shortest list worth auditing.

For the sibling case — a page or API a *person* reaches without an account, such as a magic-link landing
page — see [Public application surfaces](public-surfaces.md).
