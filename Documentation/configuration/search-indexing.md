---
title: "Search-Index Exclusion"
description: "Opt out of search indexing for every host served by an AuthProxy deployment."
---

# Search-Index Exclusion

Authentication protects application content, but a search engine can still index a sign-in page or a
URL that answers `401`. Enable `Cratis:AuthProxy:SearchIndexing:Exclude` to ask search engines to keep
all hosts served by this deployment out of their indexes.

The setting defaults to `false`. Without it, AuthProxy adds no search-index headers and `/robots.txt`
follows the same authentication and routing rules as any other application path.

## Enable exclusion

Add this section to your AuthProxy configuration:

```json
{
  "Cratis": {
    "AuthProxy": {
      "SearchIndexing": {
        "Exclude": true
      }
    }
  }
}
```

For environment-variable configuration, set `Cratis__AuthProxy__SearchIndexing__Exclude=true`.
In an Aspire AppHost with an existing AuthProxy resource, call:

```csharp
authProxy.WithSearchIndexExclusion();
```

This is a deployment-wide setting, not a service or host override. [`Services:Hosts`](one-proxy-several-hosts.md)
selects a service, while sign-in pages, errors and other proxy-owned responses belong to the shared
proxy. Use separate deployments if some hosts must remain indexable.

## Response contract

When enabled:

- `GET /robots.txt` answers anonymously with `200`, `Content-Type: text/plain; charset=utf-8` and exactly
  `User-agent: *\nDisallow: /\n` (each `\n` is a newline).
- `HEAD /robots.txt` answers with the same headers and no body.
- Those two requests never authenticate, resolve a tenant or reach an upstream. The match is the exact,
  case-sensitive path; child paths and other methods keep their existing authentication behavior.
- AuthProxy supplies `X-Robots-Tag: noindex, nofollow` on responses without an existing `X-Robots-Tag`:
  proxied responses, `401` refusals, sign-in and OAuth redirects, error and well-known pages, static
  assets, and management responses. **An upstream's existing value wins**, even if it permits indexing.
  AuthProxy does not replace or append to that value; keep upstream policies consistent with your intent.

The robots file is deliberately public even with [`CapabilityOnly` admission](admission.md). Opting in
therefore reveals that this one path exists; every other path keeps its admission behavior. Private
management-listener isolation still runs first, so that listener never serves the robots file and
management paths do not become public.

These are requests to cooperative crawlers, not access controls or a guarantee of removal from an
existing index. Keep authentication enabled, and use the search engine's removal tools when needed.

## Check the deployment

Request `/robots.txt` without a session and check its body and content type. Request a protected API
without a session and check that its `401` includes `X-Robots-Tag: noindex, nofollow`. For a proxied
response, check whether the application supplies its own policy before expecting the default header.
