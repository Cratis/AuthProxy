# Public Application Surfaces

Some parts of an application are served to someone who has no account and never will: a magic-link
landing page, a report reached by a signed URL, a public status page. The visitor is not anonymous to the
*application* — the token in their link identifies them — but they are anonymous to the **proxy**, which
has no session to check.

Declaring those paths is what [`AnonymousPaths`](services.md#anonymous-paths) is for.

> **Not on a closed deployment.** Everything on this page describes a deployment in the default
> `Public` admission mode. Under [`CapabilityOnly`](admission.md) a declared anonymous path answers the
> uniform `404` like everything else, because admission runs before authentication and decides whether
> there is anything here to reach at all. A deployment that needs both a genuinely public surface and a
> closed one needs two deployments.

---

## Declaring the surface

Name the specific paths the application serves without a session — the landing route that exchanges the
token, and the API routes it calls:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Services": {
        "core": {
          "Frontend": { "BaseUrl": "http://core-web:3000/" },
          "Backend": { "BaseUrl": "http://core:8080/" },
          "AnonymousPaths": [
            "/customer-portal",
            "/api/customer-portal"
          ]
        }
      }
    }
  }
}
```

`/customer-portal` is served by the frontend, `/api/customer-portal` by the backend — the split follows
the same `/api` rule the authenticated routes use.

### Declare the narrowest prefix that works

Entries are prefixes and cover everything beneath them. `/api/customer-portal` opens every route under it,
including ones added later by someone who does not know the prefix is public. If only some of those routes
are public, name them individually instead.

---

## What still protects the surface

The token in the link. AuthProxy does not check it — it cannot, because only the application knows how it
was minted. The application validates it on every request, exactly as it would if the proxy were not
there.

What the proxy still does:

- Strips inbound `x-ms-client-principal`, `x-ms-client-principal-id`, `x-ms-client-principal-name` and
  `Tenant-ID` headers, so a caller cannot assert an identity on the way in.
- Injects no principal headers, because there is no session.
- Leaves an authenticated visitor authenticated. A declared path is identity-*optional*, not
  identity-free: someone who happens to be signed in still arrives with their identity headers, though
  **without** a `Tenant-ID` if they have not selected a tenant. Handle a declared path as tenant-optional.

---

## Why declare it in the proxy rather than route around it

The alternative is an ingress rule above AuthProxy sending those paths straight to the service. It works,
and it costs two things worth understanding before choosing it.

**It moves the identity-trust boundary.** Bypassing the proxy makes the service directly reachable, so the
ingress rule must strip inbound `x-ms-client-principal*` and `Tenant-ID` headers itself. Stripping and
re-injecting those headers is precisely AuthProxy's job; a carve-out that forwards them unfiltered is an
authentication bypass. The rule now has to be as correct as the proxy, and it is maintained somewhere
else, by someone else.

**It weakens what you can say about the deployment.** "Public traffic reaches AuthProxy only" becomes
"public traffic reaches AuthProxy except for this list", and the list has to be re-audited whenever it
changes.

Declaring the paths inside the proxy has neither cost. Traffic still flows through AuthProxy, so the
header boundary holds and the invariant stays whole.

---

## Checking it works

An unauthenticated request to a declared path should reach the application. If it comes back as the
sign-in chooser, the declaration was not accepted — an entry that is not a rooted path of literal segments
is discarded silently, so check its spelling first. See
[Anonymous paths](services.md#anonymous-paths) for the exact rule.

If it comes back as a bare `404 Not Found` and so does every other path — including `/.cratis/providers` —
the deployment is in [`CapabilityOnly`](admission.md) admission mode, and no declaration will open it.

If the request comes back as `401` rather than the application's response, the caller was not treated as a
browser navigating to a page. That is expected for a `fetch()` or a command-line client against an
*undeclared* path — see [Unauthenticated responses](unauthenticated-responses.md).

For the sibling case, an inbound request from a system rather than a person, see
[Receiving webhooks](webhooks.md).
