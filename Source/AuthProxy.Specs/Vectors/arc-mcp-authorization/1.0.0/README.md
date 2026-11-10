# Pinned authorization vectors

Source: private `Cratis/Identity`, tag `vectors/arc-mcp-authorization/v1.0.0`,
`Source/Identity.Specs/Vectors/arc-mcp-authorization-v1/`.

`manifest.json`, `profiles-and-discovery.json`, and `CHANGELOG.md` are vendored
verbatim so CI does not need access to Identity. Do not edit these files; bump
by replacing all files from a new tag and updating `PublishedAuthorizationVectors`.
Integrity specs verify file and per-case SHA-256 hashes.

The execution spec visits every manifest ID. Its explicit not-applicable table
identifies behavior owned by Identity, Arc, or an OAuth client rather than this
gateway. Resource metadata bodies are served by the backend; AuthProxy only
forwards their requests. PAT revocation and product-policy checks are likewise
backend responsibilities.

AuthProxy does not verify sender-constraining proofs. Both bearer routes and
`Authentication:JwtBearer` refuse every access token containing a `cnf` claim
(case-insensitive, regardless of value) with HTTP 401 `invalid_token`, even when
a DPoP header is present. Introspection answers containing `cnf` are treated as
inactive regardless of `token_type`. The DPoP rejection vectors exercise this
fail-closed behavior, not individual proof-validation algorithms. The `DPoP`
authorization scheme remains unsupported. Ordinary unbound bearer tokens remain
supported.
