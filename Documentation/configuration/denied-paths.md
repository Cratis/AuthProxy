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

The guard checks three forms: the unchanged combined path, its normalized alternative, and a
normalized path from `IHttpRequestFeature.RawTarget`. The original target matters because Kestrel
can remove dot segments before encoded separators and repeated slashes are normalized. For example,
`/internal%2fa/../x` becomes Kestrel's `/x`, but the original target normalizes to `/internal/x`.

For the raw target, query and fragment suffixes are stripped before percent-decoding the path exactly
once as strict UTF-8. Malformed escapes, invalid UTF-8 and decoded control characters are refused;
`+` remains `+`. Absolute-form HTTP/HTTPS targets are validated, then their original path is extracted
without URI dot-segment normalization. A missing absolute-form path means `/`. Asterisk-form,
authority-form and unparseable non-origin-form targets have no supported path and are refused.

Both normalized alternatives map remaining `%2F`/`%2f`, `%5C`/`%5c` and literal backslashes to `/`,
collapse repeated slashes, then resolve `.` and `..` segments using RFC 3986 remove-dot-segments
semantics. Remaining `%2E`/`%2e` is treated as `.` only when identifying complete dot segments:
`.%2E` means `..`, while `report%2Epdf` remains an ordinary filename. This conservatively covers
double-encoded separators and dot segments without recursively unescaping ordinary names.

If any form equals the prefix without its trailing slash, or starts with that prefix followed by
`/`, the request is refused. The alternatives are only compared: the forwarded request is never
rewritten. Normalization also fails closed with the same empty 404 if `..` would climb above root,
a nonempty combined path is not absolute, or separator normalization times out. With no prefixes
configured, neither the path nor the raw target is inspected.

With `/internal/` configured:

| Request target | Result |
| --- | --- |
| `/internal`, `/INTERNAL/x`, `//internal/x` | 404 |
| `/internal%2Fx`, `/internal%5Cx` | 404 because the separator alternative matches |
| `/internal//../secret`, `/internal//%2e%2e/secret` | 404: Kestrel resolves these to `/internal/secret` |
| `/a/../internal/x`, `/a/%2e%2e/internal/x` | 404: Kestrel resolves these to `/internal/x` |
| `/a%2f../internal/x`, `/a%2F..%2Finternal/x`, `/a\..\internal\x` | 404: separator normalization followed by dot-segment resolution yields `/internal/x` |
| `/internal%2fa/../x`, `/a//../internal/x` | 404: the original target normalizes to `/internal/x` despite Kestrel removing segments differently |
| `/internal%252Fx`, `/a/%252e%252e/internal/x` | 404: remaining encoded separators and dot segments are normalized |
| `/a%2f..%2f..%2fpublic/x`, `/%252e%252e/public/x` | 404: above-root traversal fails closed |
| `/a/%252e%252e/public/x`, `/files/report%252Epdf` | Pass: traversal resolves outside the prefix; encoded dots within filenames are ordinary characters |
| `/a/../public/x`, `/a%2F..%2Fpublic/x`, `/internal-not/x` | Pass: the normalized path is outside the prefix |
| `/internal/../x`, `/internal/%2e%2e/x` | Pass: Kestrel resolves these to `/x`, which is outside the prefix |
| `/internally`, `/api/internal/x` | Pass: neither matches the prefix boundary |
| `/x/%20name`, `/x/a;b`, `/x/%25`, `/x/name%2Fchild` | Pass: encoded names and parameters outside the prefix are not blanket-refused |

The server can still reject invalid HTTP syntax independently of this guard. Scheme and authority
are not part of prefix comparisons. A missing or empty `RawTarget` (for example in TestServer) skips
only the raw-target check; both downstream-path checks still apply. An absent `PathBase` contributes
an empty string. The raw target already contains the full public path, so `PathBase` is not prepended
to it again.

## Shared prefixes and upstream rewriting

The guard checks the combined path before AuthProxy service-prefix stripping. If the public path is
`/shared/internal`, configure `/shared/internal`, not `/internal`, whether or not `/shared` has already
been split into `PathBase`. There is no `RequireSharedPrefixSupport` setting in AuthProxy; service
`PathPrefix`/`StripPathPrefix` rewriting happens later. An embedding host must call
`UseDeniedPathPrefixes()` before its own request handlers.

An external ingress that rewrites paths before AuthProxy must enforce the original public boundary
itself, or preserve the public path when forwarding. AuthProxy protects the path it receives and
serves, not a pre-rewrite path that is no longer available.
