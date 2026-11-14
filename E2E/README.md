# Consumer E2E lane

Builds the AuthProxy image from this working tree, runs a minimal real Arc app behind it, and drives
Arc's `/.cratis` surface from outside with a client-credentials bearer token: the refused unauthenticated
stream, the token exchange, an observable query over SSE, a command that changes what that query observes (seen on
the open stream), and the changed value over WebSocket. The sample serves generated commands under `/.cratis`
(`GeneratedApis.RoutePrefix`) so one bearer prefix covers the whole surface.

```shell
bash E2E/run.sh
```

Needs Docker Compose, OpenSSL and the .NET SDK (10 and 11). CI runs the same script (`.github/workflows/consumer-e2e.yml`).

Bearer tokens are scoped to the service's client-credentials route prefix, which this lane sets to
`/.cratis`. The bearer path does not exercise `/.cratis/me`; the cookie-session paths are covered by the
`for_ArcCratisPaths` specs in `AuthProxy.Security.Specs`.

## OAuth-grant lane

The same script also starts a throwaway HTTPS issuer and an independent, single-replica v2 receiver. It drives
REST and MCP person-token requests, validates their signed principal, tenant, grant and token-hash evidence,
and checks fail-closed gateway and receiver scenarios. The MCP-shaped test subset uses JSON-RPC `tools/list` and `tools/call` (not full MCP lifecycle/session handling);
the REST and tool-call responses expose only verified credential/person identifiers and a hash-match flag.
No deployed Identity server is needed. **The receiver is a test verifier, not product code or an Arc installer.**

The issuer's CA, TLS key and envelope signing key are generated per run under `.ai-work/e2e/` and removed after
container shutdown. CA trust is a runtime-only mount (`SSL_CERT_FILE`); validation is never disabled. Only
AuthProxy receives the envelope private key; the receiver receives only its public key. The gateway/backend
HTTP hops deliberately use `LocalDevelopment`. These unauthenticated test-control services must stay isolated.

Run the receiver's independent contract self-test without Docker:

```shell
dotnet run --project E2E/OAuthGrantReceiver/OAuthGrantReceiver.csproj -c Release -- --self-test
```

`OAuthGrantReceiver/Contract/Reference.cs` vendors the model records and reference verifier from Arc's
`Documentation/backend/csharp/asp-net-core/forwarded-identity-v2/generate-vectors/generate.cs` at revision
`de9e176d5f669e2036ff3ab5bf85f60dad6a7d9b` (lines 1–2, 8–14, 126–148 and 483–751). Its algorithms are unchanged.
`Contract/vectors.json` is the byte-for-byte fixture from that revision, including **public test-only** keys.
These fixture keys are not used for the live lane. Upgrading the contract requires reviewing the upstream
specification, verifier and all 220 vectors together, not regenerating expected output from AuthProxy.

See [Verify OAuth-grant forwarding](../Documentation/configuration/oauth-grant-e2e.md) for coverage, replay-store
limits, revocation bounds, failure diagnostics and cleanup. The receiver's hostile shim keeps captured request
material only in memory and returns scenario names, never bearer tokens or signed headers. CI uploads only
`compose.log`, excluding any runtime material retained after a failed container shutdown.

### Manual real-Identity follow-up

This automated lane uses a contract-faithful issuer, not a deployed Identity instance. A separate manual run
against real Identity must use its documented local setup and a human-obtained, unbound person token, with
normal HTTPS validation and matching issuer/audience/introspection configuration. Never store that token in
this harness, logs or artifacts. Repeat the REST/MCP evidence checks, revocation deadline and outage checks
in that isolated environment. Real Identity currently requires a GitHub OAuth app and interactive sign-in;
this repository does not automate those steps. Arc/Direct receiver verification remains a separate follow-up
until Arc exposes a public OAuth-grant receiver installer.
