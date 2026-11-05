---
title: Forwarded Identity Signing
description: Configure AuthProxy to sign outbound forwarded identity for Arc v1 receivers, including proxy, bearer, identity-details and tenant-list flows.
---

# Forwarded Identity Signing

AuthProxy can attach an HMAC-SHA256 proof to the identity headers it sends to a backend. Signing is **opt-in per flow**. An installation with no `ForwardedIdentity` blocks keeps its existing unsigned forwarding behavior.

Use an Arc receiver with the v1 contract (Arc 22.168.0 or a compatible newer version). Deploy AuthProxy signing before requiring proofs at the receiver. AuthProxy does not require an Arc package upgrade to produce this wire format.

## From Aspire

Use [`WithSignedForwardingTo(backend)`](../aspire/index.md#signed-forwarded-identity) to pair the AuthProxy signer and Arc verifier without hand-writing environment configuration. Run mode generates a fresh secret per backend; publishing requires an explicitly provisioned secret parameter. The pairing also configures resource-based selectable-tenant endpoints on that backend.

## Configure a service

Set `Cratis:AuthProxy:Services:<name>:ForwardedIdentity`:

```json
{
  "Audience": "orders-api",
  "KeyId": "orders-2026-01"
}
```

Supply the third property, `SecretBase64`, through your secret provider, for example the environment configuration key `Cratis__AuthProxy__Services__orders__ForwardedIdentity__SecretBase64`. Generate a fresh cryptographically random 32-byte secret and standard-base64 encode it. Do not put credentials in committed configuration. The published Arc test-vector key is refused at startup.

| Property | Requirement |
| --- | --- |
| `Audience` | Nonblank, 1–128 printable ASCII characters; must exactly match the receiver's audience. |
| `KeyId` | Case-sensitive `[A-Za-z0-9_-]{1,64}`; must identify a key provisioned at the receiver. |
| `SecretBase64` | Strict standard base64 encoding exactly 32 random bytes, with no whitespace. |

A partial or invalid block stops startup and identifies the configuration path, without printing the secret. There is no global signing key or fallback key. Each backend audience must have distinct key material. Service aliases may share material only with identical audience and key ID; sharing material across audiences or under different key IDs is refused. Startup identifies only the two configuration paths. Do not reuse OIDC, Data Protection or on-behalf assertion keys.

The service block covers:

- Normal proxied identity-bearing requests to that service's backend and frontend.
- Its bearer-route forwards, using the service selected by the bearer route, not a caller-supplied service marker.
- AuthProxy's direct `/.cratis/me` identity-details calls to that service.

A service whose frontend and backend verify proofs must provision the matching audience and key at both receivers, or be split into separately configured services. Anonymous requests without principal or on-behalf identity material remain unsigned; tenant or service selectors alone do not create an identity.

## Configure the tenant-list flow separately

A service block does **not** sign `TenantsEndpoint` calls. Configure `ForwardedIdentity` on the selection resolver's `Options`:

```json
{
  "Strategy": "Selection",
  "Options": {
    "TenantsEndpoint": "https://tenants.example.test/tenants",
    "ForwardedIdentity": {
      "Audience": "tenant-directory",
      "KeyId": "tenants-2026-01"
    }
  }
}
```

Supply `Cratis__AuthProxy__TenantResolutions__0__Options__ForwardedIdentity__SecretBase64` from the secret provider, adjusting the array index to the selection resolver's position. If this block is absent, the tenant flow remains unsigned even when service flows are signed. This matters when a tenant endpoint also requires signed identity.

The tenant flow may reuse its own service's key only with an identical audience and a `TenantsEndpoint` inside that service's configured backend origin and base-path boundary. Scheme, host and port must match; path comparison is case-sensitive and segment-boundary aware. A frontend URL does not establish backend ownership. Selection options have no explicit service reference, so deployments that cannot establish this relationship from their URLs must use a separate tenant-endpoint key.

## Receiver configuration and rollout

At the Arc receiver, enable both `Cratis:Arc:TrustForwardedIdentityHeaders` and `Cratis:Arc:ForwardedIdentity:Enabled`. Configure `Cratis:Arc:ForwardedIdentity:Audience` and matching `ForwardedIdentity:Keys` entries with `KeyId` and `SecretBase64`. Provision secrets through the receiver's secret provider too. An Arc verifier may accept several keys during rotation; AuthProxy emits one active key per flow.

1. Provision the receiving audience and new key without yet requiring proofs from unsigned producers.
2. Enable AuthProxy signing for **every applicable producer**, including `/.cratis/me` and the independently configured tenant endpoint. Confirm each receiving host verifies real requests.
3. Enable the receiver's signed-only verification. There is no unsigned fallback in that mode. Missing, expired, replayed, malformed or invalid proofs cannot establish forwarded identity.
4. During rotation, add the replacement key at receivers first, switch each producer's `KeyId` and secret, wait out the verifier's acceptance/replay window, and then remove the old key.

Keep clocks synchronized. Arc accepts timestamps up to 30 seconds in the future and 60 seconds old; each outbound attempt gets a fresh 256-bit nonce. Replay tracking is process-local, not a cluster-wide replay guarantee. Do not record proofs, nonces or shared secrets in request logs.

## Wire bindings and limits

AuthProxy strips caller-supplied `x-cratis-forwarded-identity-signature` values. After identity injection, path rewrites and destination construction, it emits exactly one:

```text
v1.<key-id>.<unix-seconds>.<base64url-nonce>.<base64url-hmac>
```

The proof binds the audience, key ID, timestamp, nonce, uppercase HTTP method, final escaped path and the sorted covered header set. Percent-triplet hex in the path is uppercased without decoding. The query string and body are **not** covered.

Covered headers are every `x-ms-client-principal*` and `x-cratis-on-behalf*` header, token client ID and scope, and both modern and legacy tenant and service headers. Values retain their exact printable ASCII transport representation after trimming only outer SP/HTAB. Internal commas, base64 padding and percent escapes are not normalized. At most 64 covered names and 32,768 canonical UTF-8 bytes are accepted. Repeated covered values, missing required principal fields, malformed paths and remaining controls or non-ASCII values are refused.

Arc also covers a custom `Tenancy.HttpHeader` when configured. AuthProxy signs only its fixed modern/legacy tenant headers; a receiver configured to consume another tenant header is not compatible with this producer configuration.

## Failures and diagnostics

A configured identity-bearing request that cannot be signed is not sent unsigned. Proxy and bearer flows use their existing generic forwarding-failure response. Identity-details signing refusal is an indeterminate verification result and is refused even under `BestEffort`. Tenant signing refusal uses the existing unavailable result; it does not create an empty tenant list or confirm a tenant. Signed back-channel HTTP clients do not follow redirects, so proofs cannot be replayed automatically to another destination. Legacy unsigned clients retain their previous behavior.

Startup diagnostics list each proxied, bearer, identity-details and tenant-list flow as signed or not signed, with only service, audience and key ID. Check these rows when rolling out: signing a normal request does not prove that the tenant-list flow is signed. Runtime refusals log bounded reason codes, never principal JSON, header values, secrets, canonical input, nonces or MACs.

Signing is not tenant membership, authorization, a replacement for on-behalf assertions, or body integrity. Preserve TLS, backend ingress restrictions and existing authorization checks. Anyone able to verify a shared-key proof can also forge one; constrain access to each service's signing material.
