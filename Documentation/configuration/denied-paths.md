---
title: "Denied Paths"
description: "Refuse configured public-host path prefixes before AuthProxy routing or authentication, using the same paths the downstream pipeline serves."
---

# Denied Paths

To keep an internal endpoint off the public host, configure `Ingress:DeniedPathPrefixes`:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Ingress": {
        "DeniedPathPrefixes": [ "/internal/" ]
      }
    }
  }
}
```

The equivalent environment variable is `Cratis__AuthProxy__Ingress__DeniedPathPrefixes__0=/internal/`.
The list defaults to empty; when empty, it does not inspect or refuse any paths. When enabled, the guard
answers with an empty 404 before routing, authentication, anonymous-path handling, tenant resolution,
static assets, management answers or gRPC/YARP forwarding. Refusal logs are Debug-level and contain no
path or query.

## Prefix validation

Invalid entries fail startup. Each prefix must start with `/` and contain only ASCII letters, digits,
`/` or the path characters `-._~!$&'()+,=:@`. Escapes, backslashes, dot segments, `..` anywhere,
whitespace, controls, path parameters, wildcards (`*`, `?`), query/fragment delimiters and route-template
syntax such as `{id}` are not accepted. Repeated slashes are collapsed and trailing slashes ignored
in configured prefixes. `/` refuses every request, including probes and sign-in callbacks.

## Matching the downstream path

The guard checks `Request.PathBase.Value + Request.Path.Value`, using ordinal, case-insensitive
segment-boundary comparisons. Kestrel has already decoded the path (except encoded slashes) and
resolved visible dot segments; routing and YARP use that path. Query strings never participate in matching.

Both the unchanged combined path and a normalized alternative are checked. The alternative maps
remaining `%2F`/`%2f`, `%5C`/`%5c` and literal backslashes to `/`, collapses repeated slashes, then
resolves `.` and `..` segments using RFC 3986 remove-dot-segments semantics. This order also resolves
dot segments revealed by encoded separators. If either form equals the prefix without its trailing
slash, or starts with that prefix followed by `/`, the request is refused. The alternative is only
compared: the forwarded request is never rewritten.

When prefixes are configured, normalization fails closed with the same empty 404 if `..` would climb
above root, encoded `%2E`/`%2e` forms remain after Kestrel decoding, the combined path is nonempty and
not absolute, or separator normalization times out. Remaining encoded dots are refused rather than
decoded again, including double-encoded dots that survive Kestrel. Other ordinary path characters
are unchanged. With no prefixes configured, normalization is not attempted.

With `/internal/` configured:

| Request target | Result |
| --- | --- |
| `/internal`, `/INTERNAL/x`, `//internal/x` | 404 |
| `/internal%2Fx`, `/internal%5Cx` | 404 because the separator alternative matches |
| `/internal//../secret`, `/internal//%2e%2e/secret` | 404: Kestrel resolves these to `/internal/secret` |
| `/a/../internal/x`, `/a/%2e%2e/internal/x` | 404: Kestrel resolves these to `/internal/x` |
| `/a%2f../internal/x`, `/a%2F..%2Finternal/x`, `/a\..\internal\x` | 404: separator normalization followed by dot-segment resolution yields `/internal/x` |
| `/a%2f..%2f..%2fpublic/x`, `/a/%252e%252e/public/x` | 404: above-root traversal or remaining encoded dots fail closed |
| `/a/../public/x`, `/a%2F..%2Fpublic/x`, `/internal-not/x` | Pass: the normalized path is outside the prefix |
| `/internal/../x`, `/internal/%2e%2e/x` | Pass: Kestrel resolves these to `/x`, which is outside the prefix |
| `/internally`, `/api/internal/x` | Pass: neither matches the prefix boundary |
| `/x/%20name`, `/x/a;b`, `/x/%25`, `/x/name%2Fchild` | Pass: encoded names and parameters outside the prefix are not blanket-refused |

The server can still reject invalid HTTP syntax independently of this guard. Absolute-form targets
also use Kestrel's path-only `Request.Path`; their scheme and authority are not part of the comparison.
`RawTarget` is not consulted, so its absence (for example in TestServer) does not change the decision.
An absent `PathBase` contributes an empty string; normal matching still applies to `Path`.

## Shared prefixes and upstream rewriting

The guard checks the combined path before AuthProxy service-prefix stripping. If the public path is
`/shared/internal`, configure `/shared/internal`, not `/internal`, whether or not `/shared` has already
been split into `PathBase`. There is no `RequireSharedPrefixSupport` setting in AuthProxy; service
`PathPrefix`/`StripPathPrefix` rewriting happens later. An embedding host must call
`UseDeniedPathPrefixes()` before its own request handlers.

An external ingress that rewrites paths before AuthProxy must enforce the original public boundary
itself, or preserve the public path when forwarding. AuthProxy protects the path it receives and
serves, not a pre-rewrite path that is no longer available.
