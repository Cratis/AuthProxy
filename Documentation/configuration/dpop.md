---
title: "DPoP proof verification"
description: "Enable RFC 9449 proofs on OAuth-only AuthProxy routes with a trusted public origin, shared Redis replay protection and optional resource-server nonces."
---

DPoP is **off by default**. An OAuth-only bearer route can opt in by adding `Dpop`.
A bound token must then use `Authorization: DPoP <access-token>` and exactly one
`DPoP` header containing a signed proof. A bound token sent as Bearer is refused;
it never becomes an ordinary bearer credential.

```json
{
  "Cratis": {
    "AuthProxy": {
      "Dpop": {
        "NonceRequired": false,
        "ReplayStore": {
          "Redis": {
            "KeyPrefix": "example-deployment:dpop"
          }
        }
      },
      "Services": {
        "direct": {
          "Backend": { "BaseUrl": "https://backend.example.test/" },
          "BearerRoutes": [
            {
              "PathPrefix": "/direct-api",
              "Issuers": [{ "Issuer": "https://issuer.example.test" }],
              "Audiences": ["direct-api"],
              "ResourceMetadataUrl": "https://api.example.test/.well-known/oauth-protected-resource",
              "Dpop": {
                "Mode": "Accept",
                "PublicOrigin": "https://api.example.test",
                "PublicPathPrefix": "/mcp"
              }
            }
          ]
        }
      }
    }
  }
}
```

Supply `Cratis__AuthProxy__Dpop__ReplayStore__Redis__ConnectionString` through your
normal secret mechanism before starting this configuration. Do not commit a Redis
credential. `ReplayStore:Redis` is separate from `DataProtection:Redis`; configuring
one does not implicitly configure the other.

## Route policy and public target

- `Mode: Accept` (the default) requires proof for bound tokens and still accepts
  unbound tokens presented as Bearer without a proof header.
- `Mode: Require` requires a bound token and DPoP presentation on every request.
- `PublicOrigin` is a required HTTPS origin with no trailing slash, path, user
  information, query or fragment. Configure the externally visible authority, not
  an internal listener or a caller-supplied host.
- `PublicPathPrefix` is optional. It replaces the route's internal mount while
  retaining its relative escaped suffix. Substitution requires an ordinal,
  case-sensitive internal mount match at a complete path-segment boundary;
  differently cased mounts are refused. Without it the expected public path is
  the server's `PathBase` plus `Path`.

In the example, internal `/direct-api/tools?limit=1` expects proof `htu` exactly
`https://api.example.test/mcp/tools`. Query strings are excluded. Do not normalize
path case, trailing slashes, percent-escape case, unreserved escapes or dot
segments when constructing a proof. Ambiguous paths are refused rather than
repaired. Matching is literal: `https://api.example.test:443/mcp/tools` is refused
when the expected target is `https://api.example.test/mcp/tools`, even though the
port is HTTPS's default. `Host`, `Forwarded` and `X-Forwarded-*` never select the
trusted origin.

DPoP cannot be enabled on PAT-only or combined PAT/OAuth routes. AuthProxy also
refuses startup if a DPoP route forwards Authorization, permits fail-open
introspection, lacks a trusted origin, or lacks the shared-store configuration.
Move an OAuth endpoint to its own route rather than enabling DPoP on a combined
route. Existing routes without `Dpop` retain their sender-constraint rejection.
`Authentication:JwtBearer` is unchanged and does not verify DPoP.

DPoP routes accept externally validated OAuth JWTs, not AuthProxy's locally
protected client-credentials-issued tokens. They deliberately bypass the local
client-credentials recognizer, including in `Accept` mode. Use a separate route
without `Dpop` for those local tokens. Multiple Authorization headers, a
comma-combined Authorization value or an `access_token` query parameter are
refused before token validation with HTTP 400 `invalid_request`; AuthProxy never
chooses between competing credentials.

## Proof and replay rules

The proof profile accepts **ES256 only**, with an inline public EC P-256 JWK and a
64-byte P1363 signature. Other algorithms, private/symmetric key material, remote
key URLs, certificate headers, critical extensions, duplicate JSON names and
malformed encodings are refused. Public points must be on P-256. The JWK member
allowlist also refuses `ext`, including `ext: true`; this is an intentional
fail-closed profile choice. Proofs are limited to 4096 ASCII bytes; each JSON
segment is limited to 2048 decoded bytes and depth four. `jti` must contain 22–256
visible ASCII characters. `htm` is an exact, case-sensitive method match; `ath` is
the SHA-256 base64url hash of the exact access token. The public-key thumbprint must
match the token's unique `cnf.jkt`.

Proofs must satisfy `now - 300 < iat <= now + 30`. Every accepted identifier is
reserved atomically in Redis for **390 seconds**, scoped by the resource domain,
configured public origin and key thumbprint. Replica-local introspection caching
never caches proof decisions. Introspection must preserve the JWT's matching
`cnf.jkt` and, when present, a consistent `token_type`.

Missing, oversized, malformed or multiple proofs are refused before any Redis
operation. Cheap header and request-claim checks precede key import and signature
verification. Proof verification precedes access-policy and tenant verification,
so invalid proofs receive HTTP 401 without consulting either verifier.

A separate Redis health/clock probe is coalesced and cached for at most ten
seconds per process, including failed probes. Every replay reservation still
atomically checks Redis time, clock offset and replay coverage; cached health
never authorizes forwarding. A local/server offset greater than 30 seconds, an
unavailable store or an uncertain reservation refuses the request; there is no
process-local replay fallback. Initial startup and loss of the persistent
coverage marker impose a **390-second quarantine**. The marker records Redis time;
requests stay refused until replay coverage is re-established.

Use a dedicated, persistent, **no-eviction** Redis deployment/database. All replicas
must use the same connection/database and deployment-specific `KeyPrefix`. Keys
use an internal Redis Cluster hash tag around that prefix and hashed identifiers;
raw tokens, proofs and identifiers are never Redis key names. Do not delete replay
keys or their coverage marker while the deployment is accepting traffic. A failover
that loses replay keys without losing the marker is outside this safety contract:
quarantine the deployment for 390 seconds before resuming proof traffic. Treat
replay-store availability, persistence, capacity and NTP monitoring as security
requirements, not optional cache tuning.

## Optional resource-server nonces

`Cratis:AuthProxy:Dpop:NonceRequired` defaults to `false`. When off, supplied nonce
values do not influence verification and no nonce-specific challenges are issued.
When on, a missing, stale, tampered or incorrectly bound nonce produces HTTP 401
`use_dpop_nonce` with a fresh `DPoP-Nonce`. Successful proofs rotate the nonce too.
A replay refusal after proof verification can also return a fresh nonce. Invalid
or structurally malformed proofs do not trigger Redis health probes or issue
nonces; send a valid signed proof to obtain a nonce challenge. No nonce is issued
when the health probe reports uncertain replay-store health or clock alignment.

Nonces use the shared ASP.NET Core Data Protection key ring, a dedicated
`Cratis.AuthProxy.Dpop.Nonce.v1` purpose and random 128-bit material. They are bound
to the resource validation domain, public origin, key thumbprint and issuance time.
They expire at 330 seconds and are never accepted more than 30 seconds in the
future. Every replica must share the same protected key ring. Token-endpoint
nonces are not interchangeable with these resource-server nonces. Clients must
create a new proof and `jti` when retrying a nonce challenge.

DPoP refusals are non-cacheable machine responses, never redirects or cookie
challenges. Proof/store/clock/replay failures use HTTP 401 `invalid_dpop_proof`;
valid proofs lacking scope use HTTP 403 `insufficient_scope`. DPoP challenges
advertise `algs="ES256"` and do not suggest downgrading to Bearer. Logs contain
fixed reason codes only, not tokens, proofs, keys, nonces or full request URLs.

## Forwarding boundary

Proof verification carries only standard-base64 UTF-8 JSON `{"jkt":"…","jti":"…"}`
inside `BearerForwardedIdentity.SenderBinding`; unbound requests carry `none`.
The existing sender-evidence wire encoding is unchanged. Raw Authorization and
DPoP headers are stripped at the forwarding boundary. This feature does **not**
enable an OAuth-grant v2 signing producer, grant lookup, actor resolution or a new
forwarded-envelope kind; those remain separate integration work.
