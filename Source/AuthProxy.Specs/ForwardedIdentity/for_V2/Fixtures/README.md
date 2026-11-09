# Arc v2 conformance vectors

TEST ONLY: these published private keys and fixture credentials are public. Never deploy them.

Copied unchanged from Cratis/Arc commit `de9e176d5`,
`Documentation/backend/csharp/asp-net-core/forwarded-identity-v2/forwarded-identity-v2-vectors.json`.
SHA-256: `4b833f0ab9e9d578762385a953a58e5614a4238f3b3f74997254fbc449026d74`.

All 220 cases are exercised. The test-only consumer checks envelope grammar, freshness,
signatures, trusted metadata/bearer agreement, authenticated transport and replay classes.
Only producer responsibilities ship in AuthProxy; no backend nonce store is implemented here.
