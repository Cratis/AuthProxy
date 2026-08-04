# Unauthenticated Responses

AuthProxy answers a caller that cannot proceed in one of two ways: it serves a page, or it returns a
status code. Which one it picks depends on the caller, not on the path.

---

## Why the caller decides

The provider-selection and tenant-selection pages are HTML, and HTML has to be delivered with a success
status to render. That is the right answer to a person in a browser, and the wrong answer to everything
else:

- A webhook, an e-signing callback or any server-to-server integration reads **HTTP 200** as *delivered*.
  It does not retry, nothing is queued for redelivery, and nothing errors — so a refused request looks
  exactly like a successful one.
- A frontend's `fetch()` passes the conventional `response.ok` check and only fails later, when parsing
  HTML as JSON. Arc's own identity bootstrap calls `/.cratis/me` on boot and hits precisely this.

So AuthProxy serves a page only to a caller that is navigating to one, and refuses everyone else with a
status code they can act on.

---

## The rule

| Caller | Response |
|--------|----------|
| A browser navigating to a document | The page — provider selection at `200`, or a redirect to the identity provider |
| Anything else | `401 Unauthorized`, or `403 Forbidden` when the caller is already authenticated |

A caller is treated as navigating when either:

1. It sends `Sec-Fetch-Dest: document` (or `iframe` / `frame`). Every current browser sends this header on
   every request, and it is the only signal that separates a navigation from a `fetch()` issued by the
   *same* browser on the *same* connection.
2. It sends no `Sec-Fetch-Dest` at all — a client predating fetch metadata — **and** names `text/html`
   explicitly in `Accept`.

A wildcard `Accept: */*` does not count. That is what `fetch()`, `curl` and most webhook senders send, and
reading it as "HTML will do" is what produced the `200` in the first place. A caller that states nothing
at all is treated as an API caller, because it almost always is.

---

## What returns what

| Situation | Browser navigation | Other callers |
|-----------|--------------------|---------------|
| Unauthenticated, multiple providers configured | `200` + `select-provider.html` | `401`, no page, no `.cratis-providers` cookie |
| Unauthenticated, one provider configured | `302` to the provider | `401` |
| Unauthenticated, no providers configured | Forwarded | Forwarded |
| Authenticated, tenant selection required | `200` + `select-tenant.html` | `403`, no page, no `.cratis-tenants` cookie |
| Lobby mode, no invitation | `401` + `invitation-required.html` | `401` + `invitation-required.html` |

Two rows are worth reading twice.

**No providers configured** is forwarded either way. With nothing to authenticate against there is no
refusal to convert, and refusing here would turn a proxy that challenges nobody into one that refuses
everybody.

**Tenant selection returns `403`, not `401`.** The caller is authenticated; answering `401` would send a
frontend back through a login it has already completed. This matches the `403` AuthProxy already returns
when an authenticated user belongs to no organization.

---

## Consequences for clients

- `!response.ok` is now a correct check against AuthProxy for any non-navigating caller. It was not
  before.
- A client that deliberately wants the selection page — a custom login shell rendering it in a frame, for
  instance — should send `Sec-Fetch-Dest: document`, or navigate to `/.cratis/select-provider` directly.
  That path is in the authentication UI skip list and is never intercepted.
- Paths a service declares in [`AnonymousPaths`](services.md#anonymous-paths) never reach any of this.
  They are forwarded to the application, which answers them itself.
