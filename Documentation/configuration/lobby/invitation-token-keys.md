---
title: "Invitation token keys"
description: "Validate Ante invitation tokens with published issuer metadata and public signing keys, including key rotation and bounded outage behavior."
---

Configure invitation-token metadata to keep AuthProxy's verification keys in step with Ante's published keys.
AuthProxy checks the issuer and audience against your configuration and selects the signing key by the token's
`kid`. A successful refresh replaces the key set, so removing a published key revokes it in AuthProxy after refresh.

## Configure metadata validation

This requires Ante 1.4.0 or later with `Ante:Invitations:Token:PublicBaseUrl` set. Both
`/.well-known/ante/invitation-token` and `/.well-known/ante/jwks.json` must be reachable from AuthProxy without
sign-in. If Ante publishes under a path prefix, include that prefix in `TokenMetadataUrl`.

```json
{
  "Cratis": {
    "AuthProxy": {
      "Invite": {
        "TokenMetadataUrl": "https://lobby.example.com/.well-known/ante/invitation-token",
        "Issuer": "urn:cratis:ante:store:namespace",
        "Audience": "urn:cratis:ante:store:namespace:lobby"
      }
    }
  }
}
```

Use the issuer and audience Ante logs at startup, not values inferred from a token or a downloaded document.
The usual shapes are `urn:cratis:ante:{EventStore}:{Namespace}` and
`urn:cratis:ante:{EventStore}:{Namespace}:lobby`. Both values are required and must match the metadata exactly,
including case and whitespace. `PublicKeyPem` must be empty when `TokenMetadataUrl` is set; configuring both
fails startup validation rather than combining trust anchors.

This configuration changes verification of the incoming invitation token only. The separate AuthProxy attestation
keys and the signed stage/completion protocol remain unchanged.

## Verification boundaries

Metadata mode accepts only RS256 tokens with a nonempty `kid`, a matching configured issuer and audience, and a
valid lifetime. Tokens from before Ante 1.0 that have no `kid` or issuer are refused in this mode. AuthProxy never
uses a token-provided URL to discover a key.

The JWKS URL must be absolute and use the same scheme, host, and port as the configured metadata URL. HTTPS is
required except for HTTP on loopback. Queries, fragments, and user information are not allowed. Neither metadata
nor JWKS requests follow redirects.

Only public RSA keys with a unique, nonempty `kid` and at least 2048 bits are usable. If present, `use` must be
`sig` and `alg` must be `RS256`. Every key sharing a duplicate identifier is ignored. Any private or symmetric
key material rejects the entire response, even on an otherwise unusable key. A response with no usable keys
replaces the previous set with an empty set, refusing all tokens until usable keys are published.

Each response is limited to 64 KiB and 10 seconds, and a JWKS may contain at most 16 entries. Oversized, malformed,
redirecting, or mismatched responses fail closed; their keys never replace the last successful set.

## Refresh and outages

The automatic refresh interval uses the smaller `Cache-Control: max-age` of the metadata and JWKS, clamped to
60 seconds through 12 hours. Missing cache lifetimes default to 12 hours; `no-cache` or `no-store` uses the
60-second floor. Ante currently publishes a five-minute cache lifetime.

A due refresh runs in the background while known keys remain usable. An unknown `kid` can trigger a requested
refresh at most once every 30 seconds for the configured metadata URL, issuer, and audience, followed by one
lookup retry. Failed fetches also back off for 30 seconds.

After a failed refresh, AuthProxy may use the last successful keys for at most 24 hours from their fetch time.
Beyond that limit it refuses invitations unless a fresh retrieval succeeds. With nothing cached, every invitation
is refused until the issuer is available. Key retrieval is lazy: AuthProxy does not require Ante to be available
at startup.

## Migrate from a pinned public key

1. Upgrade Ante and configure its public base URL so both endpoints are reachable from AuthProxy.
2. Read the issuer and audience from Ante's startup output.
3. Remove `Invite.PublicKeyPem` and set `Invite.TokenMetadataUrl`, `Invite.Issuer`, and `Invite.Audience` together.
4. Use a newly issued invitation to verify the flow. Older invitations without `kid` or issuer cannot be used
   in metadata mode.

Leaving `TokenMetadataUrl` unset keeps the existing pinned-key behavior: `PublicKeyPem` verifies the token,
issuer and audience remain optional, and no metadata is fetched.
