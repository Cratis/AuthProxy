---
title: Forwarded Identity Signing
description: Sign the identity headers AuthProxy forwards to backends: default v1 HMAC-SHA256 proofs, opt-in v2 ES256, per-service audience, key ID and secret settings.
---

# Forwarded Identity Signing

**Version selection:** `ForwardedIdentity.Version` defaults to `v1`, preserving existing behavior. Explicit `v2` selects ES256 with no negotiation, unsigned bypass, or v1 fallback. The v2 trusted-context producer supports only newly signed-in Cratis Identity browser sessions; legacy sessions and every other credential kind are refused. See [v2 infrastructure](#v2-infrastructure) before configuring it.

AuthProxy can attach an HMAC-SHA256 proof to the identity headers it sends to a backend. Signing is **opt-in per flow**. An installation with no `ForwardedIdentity` blocks keeps its existing unsigned forwarding behavior.

Signed service backends and signed tenant-list endpoints require HTTPS and a configured client certificate outside AuthProxy's explicit `LocalDevelopment` profile. Configure [Backend TLS](backend-tls.md) before enabling signing in a deployed environment. Signing protects the forwarded identity proof; it does not replace transport authentication or backend ingress restrictions. Installations that do not configure signing retain their existing transport behavior.

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

A partial or invalid block stops startup and identifies the configuration path, without printing the secret. There is no global signing key or fallback key. Each backend audience must have distinct key material. Service aliases may share material only with identical audience, key ID and normalized backend destination (scheme, host, port, credentials and exact path). Missing or ambiguous destinations, including query/fragment-bearing base URLs and DNS-discovered replica routing, cannot establish alias ownership. Sharing material across audiences, under different key IDs or across destinations is refused. Startup identifies only the two configuration paths. Do not reuse OIDC, Data Protection or on-behalf assertion keys.

The service block covers:

- Normal proxied identity-bearing requests to that service's backend and frontend.
- Its bearer-route forwards, using the service selected by the bearer route, not a caller-supplied service marker.
- AuthProxy's direct `/.cratis/me` identity-details calls to that service.
- Sign-in callbacks to that service. Each delivery attempt gets a fresh proof; a configured callback that cannot be signed is not sent. Unsigned services keep their existing callback behavior in mixed deployments.

A service whose frontend and backend verify proofs must provision the matching audience and key at both receivers, or be split into separately configured services. Anonymous requests without principal or on-behalf identity material remain unsigned; tenant or service selectors alone do not create an identity.

## Optional browser-session context

Set `Cratis:AuthProxy:Services:<name>:ForwardSessionContext` to `true` to add browser-session context
only to that service's normal proxied `x-ms-client-principal` envelope. It defaults to `false`:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Services": {
        "orders": {
          "ForwardSessionContext": true
        }
      }
    }
  }
}
```

- `urn:cratis:session:started` is the original completed sign-in time in Unix seconds. AuthProxy records
  it in protected cookie-ticket properties; sliding cookie renewal and provider-token refresh do not
  move it. It is not `auth_time`, an identity-provider authentication or reauthentication assertion.
- `urn:cratis:session:sign-in-provider` is AuthProxy's recorded scheme name, for example `microsoft`
  or `github`. It names the sign-in handler, not an issuer, subject, actor, or tenant.

Both values come from AuthProxy-authored protected session state, never upstream claims, invite
metadata, or request headers. Legacy cookies without a recorded start omit `started`; AuthProxy does
not fabricate a time from cookie issuance, expiry, current time, or `auth_time`. A missing recorded
provider is likewise omitted. No new top-level envelope fields or separate headers are introduced.
With the setting off, the existing envelope is unchanged except that forged reserved claims are removed.

The route-selected service controls the opt-in, not caller-supplied service headers or query parameters.
It does not add context to `/identity`, identity-details back channels, or callbacks, nor does it
synthesize browser context for bearer, client-credential, or capability credentials. Token-supplied
copies of these two reserved claims are removed from bearer envelopes.

When forwarded-identity signing is enabled, the existing proof covers the complete principal envelope,
including these claims. A backend must verify the proof before relying on session context; unsigned
headers alone are not trusted evidence. Enabling this option does not enable signing, upgrade v1 to v2,
or change v2's supported credential kinds or schema. A verified scheme still does not replace the
canonical issuer/subject or actor attribution.

## Bearer resource and scheme

A validated access-token principal carries exactly one `urn:cratis:bearer:resource` claim: the configured
resource audience that exactly matched its `aud`, before claim mappings. When several configured
audiences match, the ordinal-first match wins. No trailing-slash normalization is applied. Token-supplied
claims in this reserved namespace are stripped. The claim is inside the signed `x-ms-client-principal`
when signing is enabled; it does not replace the envelope's configured backend `Audience`.

Bearer forwards also replace `X-Forwarded-Proto` with the effective request scheme after trusted
forwarded-header processing, never a caller-supplied value. This header is not itself part of the v1
signed envelope; protect the backend hop and restrict backend ingress as described above. See the
[bearer forwarding contract](authentication.md#https-is-required) for transport exemptions.

## Other identity back channels

On-behalf grant checks and session notifications retain their per-call attestations, bound to purpose, method, target and body. They do not carry the v1 header envelope and are reported as attested, not envelope-signed. Their signed service's backend requires HTTPS outside `LocalDevelopment`, and their backend hosts receive the configured client certificate.

Invitation staging/exchange, link exchange, and sign-in notifications are reported for transport only. Their body identity is not covered by the v1 envelope; invitation and sign-in notifications retain their flow-specific attestations.

When any forwarded-identity signing is configured, callback backend URLs, resolved client-credential verification endpoints, invitation staging/exchange, link exchange, sign-in notification, capability verification, and tenant verification URLs must use HTTPS outside `LocalDevelopment`. A client-credential `VerificationPath` may be an absolute HTTP/HTTPS URL or backend-relative; validation checks the same resolved endpoint the verifier calls, not just the backend URL. Leading-slash paths, including the default `/.cratis/client-credentials/verify`, retain the backend's scheme and authority and resolve at its origin root. An empty or relative backend URL produces a validation failure when the endpoint needs a backend, rather than a URI parsing exception.

Client-credential and capability verifier destinations, queued callback destinations, resolved tenant-verification URLs, and discovered OIDC token endpoints are checked against the current configuration before a client is created. Queued callbacks also use the current signing settings on every attempt. `LocalDevelopment` retains the existing HTTP allowance. Unsigned deployments retain their existing transport behavior.

Capability/tenant verifiers and identity providers do not extend the backend client-certificate host set. They receive the backend client identity only if their host is independently configured as a backend hop; see [Backend TLS](backend-tls.md).

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

AuthProxy strips caller-supplied `x-cratis-forwarded-identity-signature` values and known forwarded-identity context headers, including older draft names, treating underscore spellings of protected names as their hyphenated equivalents. After identity injection, path rewrites and destination construction, it emits exactly one:

```text
v1.<key-id>.<unix-seconds>.<base64url-nonce>.<base64url-hmac>
```

The proof binds the audience, key ID, timestamp, nonce, uppercase HTTP method, final escaped path and the sorted covered header set. Percent-triplet hex in the path is uppercased without decoding. The query string and body are **not** covered.

Covered headers are every `x-ms-client-principal*` and `x-cratis-on-behalf*` header, token client ID and scope, and both modern and legacy tenant and service headers. Values retain their exact printable ASCII transport representation after trimming only outer SP/HTAB. Internal commas, base64 padding and percent escapes are not normalized. At most 64 covered names and 32,768 canonical UTF-8 bytes are accepted. Repeated covered values, missing required principal fields, malformed paths and remaining controls or non-ASCII values are refused.

The signed principal can carry an `auth_time` claim, in Unix seconds, when a service uses [fresh authentication](fresh-authentication.md). A receiver may rely on it only after the proof verifies.

Arc also covers a custom `Tenancy.HttpHeader` when configured. AuthProxy signs only its fixed modern/legacy tenant headers; a receiver configured to consume another tenant header is not compatible with this producer configuration.

## Failures and diagnostics

A configured identity-bearing request that cannot be signed is not sent unsigned. Proxy and bearer flows use their existing generic forwarding-failure response. Identity-details signing refusal is an indeterminate verification result and is refused even under `BestEffort`. Tenant signing refusal uses the existing unavailable result; it does not create an empty tenant list or confirm a tenant. Signed back-channel HTTP clients do not follow redirects, so proofs cannot be replayed automatically to another destination. Legacy unsigned clients retain their previous behavior.

Startup diagnostics list each proxied, bearer, identity-details, tenant-list and sign-in callback flow as signed or not signed, with only service, audience and key ID. On-behalf calls are listed as attested, not envelope-signed. Invitation staging/exchange, link exchange and sign-in notifications have transport-only rows. Check these rows when rolling out: signing a normal request does not prove that the tenant-list flow is signed. Runtime refusals log bounded reason codes, never principal JSON, header values, secrets, canonical input, nonces or MACs.

Signing is not tenant membership, authorization, a replacement for on-behalf assertions, or body integrity. Preserve TLS, backend ingress restrictions and existing authorization checks. Anyone able to verify a shared-key proof can also forge one; constrain access to each service's signing material.

## V2 infrastructure

V2 implements the [Arc signed-forwarded-identity v2 contract](https://github.com/Cratis/Arc/blob/de9e176d5/Documentation/backend/csharp/asp-net-core/signed-forwarded-identity-v2.md). The built-in producer supports **Cratis Identity browser sessions only**. Existing sessions must sign in again to obtain protected v2 evidence; enabling v2 does not upgrade legacy tickets. V1 remains the default. Do not switch a production flow to v2 until its credential pipeline supplies verified evidence and its receiver explicitly supports v2.

For any existing per-flow `ForwardedIdentity` block:

- Set `Version` to the exact string `v2`.
- Set `Audience` to a 1–64 character lowercase slug: letters/digits separated by single hyphens, starting with a letter.
- Set `KeyId` to 1–64 ASCII letters, digits, underscores or hyphens.
- Supply `PrivateKeyPkcs8Base64` through the deployment's secret mechanism: strict standard-base64 PKCS#8 DER containing a P-256 private key. PEM, public-only keys, other curves, trailing bytes and whitespace are refused.
- Set `TenantHeader` to the receiver host's tenancy header if it differs from `x-cratis-tenant-id`. The gateway strips this header and its underscore aliases inbound, then emits only its resolved tenant. Reserved identity, authentication, callback, hop-by-hop, forwarding and content headers are refused as tenancy headers, including underscore aliases. The canonical `x-cratis-tenant-id` remains valid; the legacy `Tenant-ID` alias is reserved.
- Leave `SecretBase64` empty. V1 shared material and v2 private material must never be mixed. Existing Aspire pairing helpers remain v1-only; do not give a v2 private key to a backend or to a v1 helper.

The existing HTTPS/mTLS and cross-application key/audience reuse checks apply to v2. Receivers get **only the public key**, under the matching audience and key ID. Keep old public keys during the receiver's permitted rotation window; pin one active private key on each producer flow. There is no algorithm negotiation, key discovery or receiver fallback. The producer caches one synchronized ECDsa handle per private key, disposing handles on configuration reload and shutdown. Temporary private-key import buffers are cleared; validation retains only a public-key fingerprint for reuse detection. P-256 recognition supports both its OID and reviewed platform friendly names when no OID value is available.

A trusted pipeline supplies one immutable `ForwardedIdentityTrustedContext` through `HttpRequestMessage.Options` using `ForwardedIdentityTrustedContext.OptionsKey` before the final signing hop. This record is not deserialized from HTTP headers. It carries authoritative credential kind and non-secret record ID, verified sender evidence (or explicit `none`), allowlisted realm issuer, preserved person issuer/subject/identity-provider/authentication-time/strength evidence, and optional methods, actor, checked grant and policy revision. Original authentication time is never minted from refresh or proof issuance time. Only the reviewed ACR value `basic` is currently accepted; all other authentication-strength strings are refused until explicitly reviewed. Service callers omit person evidence; they are not promoted to people.

At a completed sign-in, only an explicitly configured `CratisIdentity` OIDC provider can create browser evidence. The realm issuer, UUID-v4 subject, upstream `idp` and original `auth_time` must come from verified realm tokens and agree with the canonical principal and the preserved authentication time. Missing evidence is refused, independently of sign-in notification configuration. An arbitrary canonical provider is not a Cratis Identity realm. A fresh random credential ID is protected in the cookie ticket and survives sliding renewal alongside the original authentication time. Browser cookies are unbound credentials (`sender-binding: none`); assurance is conservatively `basic`.

PATs, OAuth bearer grants, on-behalf sessions, machine principals and workloads remain unsupported by this browser-session envelope producer and fail closed, including explicit contexts of these kinds. [DPoP-enabled OAuth-only routes](dpop.md) can independently verify proofs and carry standard-base64 JSON sender evidence internally; this does not enable signing OAuth-grant envelopes. An inbound Authorization or DPoP header alongside a cookie is also refused. No client ID, token `jti`, caller header, cookie renewal time or proof issuance timestamp can substitute for session evidence.

The signer replaces all inbound v2 context headers with independently verified evidence, validates principal/account-key agreement, and covers the entire v2 allowlist plus `context.TenantHeader` (default `x-cratis-tenant-id`). Duplicate covered headers, including duplicates in content headers, are refused. The canonical input starts with `Cratis.AuthProxy.ForwardedIdentity.v2`; the envelope is `v2.keyId.timestamp.nonce.signature`, with a fresh 16-byte unpadded base64url nonce and a 64-byte IEEE P1363 ES256 signature. Query strings and bodies remain outside the signature; authenticated transport and receiver authorization remain mandatory.

**Absent or incomplete trusted context returns `ForwardedIdentitySigningOutcome.Refused`, even for a request without identity headers.** The normal signed transports then stop the request. No unsigned or v1 fallback is permitted. Proxied browser requests, identity-details calls and tenant-list calls use only the selected protected cookie ticket. Sign-in callbacks carry an immutable snapshot of that evidence across queueing and retries. The snapshot expires 60 seconds after it is queued; every attempt checks that original deadline, and retries cannot extend it. A custom signer host without `IHttpContextAccessor` logs a warning on first v2 use and must supply an explicit trusted snapshot. Per-flow diagnostics include the wire version and report v2 as `browser-session-only`, not universal credential support. Receiver freshness checks, nonce stores and replay policy are receiver responsibilities; this producer does not implement them.

The conformance specs vendor all 220 Arc vectors from commit `de9e176d5`. They reproduce every accepting canonical input byte-for-byte and verify generated P1363 signatures against the supplied public keys, exercise all reference outcomes with a test-only consumer, and separately refuse producer-applicable malformed snapshots and metadata. All published fixture keys are **TEST ONLY** and must never be deployed.
