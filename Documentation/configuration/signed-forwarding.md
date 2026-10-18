# Signed Forwarding

AuthProxy tells a service who is calling through headers: `x-ms-client-principal*` for the user,
`x-cratis-tenant-id` for the tenant, `x-cratis-token-*` for a bearer caller. A service that believes those
headers has to trust the network: anything that can reach the service directly can write them too.

Signed forwarding removes that assumption. AuthProxy signs a short-lived ES256 assertion over the headers it
sends and attaches it to every request in `x-cratis-forwarded-identity`. A service that verifies the
assertion knows the identity and tenant headers were written by your AuthProxy deployment, for this service,
for this exact request.

It is **off by default**. Without `Cratis:AuthProxy:ForwardingAttestation`, requests are forwarded exactly as
before.

---

## What AuthProxy sends

Once signed forwarding is configured, AuthProxy adds one header:

```text
x-cratis-forwarded-identity: <compact JWS>
```

It is attached to:

- every request AuthProxy proxies to a service backend or frontend, including anonymous requests and requests
  on [bearer routes](services.md#bearer-routes);
- the `/.cratis/me` call AuthProxy makes to [resolve identity details](services.md#identity-enrichment);
- the call to the [tenant-selection endpoint](tenant-selection.md).

An anonymous request is signed too: its assertion simply has no `sub` claim, so a service can tell
"AuthProxy forwarded this with no user" from "someone wrote the headers themselves".

AuthProxy **always removes** an `x-cratis-forwarded-identity` header sent by the caller, whether signed
forwarding is configured or not. A caller can never supply its own assertion.

---

## The assertion

The assertion is a compact JWS. The protected header is exactly:

```json
{"alg":"ES256","typ":"cratis-fwd+jwt","kid":"<ActiveKeyId>"}
```

The payload is JSON with no whitespace and its members in this order:

| Claim | Value |
|---|---|
| `iss` | The configured `Issuer`. |
| `aud` | The audience of the target service. See [Audiences](#audiences). |
| `iat`, `nbf` | The signing time, in seconds since the Unix epoch. |
| `exp` | `iat` plus the configured `Lifetime`. |
| `jti` | 128 random bits, base64url-encoded, fresh for every request. |
| `htm` | The method of the outbound request, for example `POST`. |
| `htp` | The path of the outbound request, without the query. |
| `sub` | The value of `x-ms-client-principal-id`. Omitted when the request is anonymous. |
| `tid` | The value of `x-cratis-tenant-id`. Omitted when the request carries no tenant. |
| `fwh` | The digest of the bound headers. See [The header digest](#the-header-digest). |

The signature is ECDSA P-256 with SHA-256 in the JWS fixed-length `r || s` form, and every segment is
unpadded base64url.

`htp` is the path AuthProxy **sends**, after path transforms: with `StripPathPrefix` the prefix is gone, and a
backend `BaseUrl` with a path contributes that path. It is the percent-encoded form, as it appears on the wire.
A service compares it with the path it receives, so **anything between AuthProxy and the service that rewrites
the path is not supported** while the service verifies assertions. A query string is outside the binding.

A deterministic set of test vectors (a fixed key pair, the canonical header string, the digest, the signing
input and a complete token) is in
[golden-vectors.json](https://github.com/Cratis/AuthProxy/blob/main/Source/AuthProxy.Specs/ForwardedIdentity/golden-vectors.json).

---

## The header digest

`fwh` binds the identity and tenant headers to the assertion. AuthProxy builds a canonical string from these
headers, in this order:

1. `x-ms-client-principal`
2. `x-ms-client-principal-id`
3. `x-ms-client-principal-name`
4. `x-ms-client-principal-name*`
5. `x-cratis-tenant-id`
6. `tenant-id`
7. `x-cratis-token-client-id`
8. `x-cratis-token-scope`

For each header present on the outbound request it appends `name:value\n`: the name in the lowercase form
above, the value with surrounding spaces and tabs removed. Absent headers contribute nothing, so a request
with none of them gives the empty string. `fwh` is the unpadded base64url SHA-256 of the UTF-8 string.

A bound header that occurs more than once, or whose value carries a line break, cannot be canonicalized.
AuthProxy does not sign such a request and answers `502` instead of forwarding it.

---

## Audiences

`aud` names the service a request is for, so a service cannot replay an assertion it received to a sibling.
A service's audience is its `ForwardingAudience`, or its configuration key when that is unset:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Services": {
        "reports": {
          "Backend": { "BaseUrl": "http://reports-api:8080/" },
          "ForwardingAudience": "reports-api"
        },
        "catalog": {
          "Backend": { "BaseUrl": "http://catalog-api:8080/" }
        }
      }
    }
  }
}
```

Requests to `reports` are signed for `reports-api`; requests to `catalog` for `catalog`. The service's
verifier must expect exactly this value.

The tenant-selection endpoint is a URL, not a service, so AuthProxy looks for the service that serves it: the
configured service whose backend has the same scheme, host and port. When several do, the one whose backend
path is the longest prefix of the endpoint's path wins. When no service serves the endpoint, or the remaining
services disagree on the audience, set it on the selection strategy:

```json
{
  "Cratis": {
    "AuthProxy": {
      "TenantResolutions": [
        {
          "Strategy": "Selection",
          "Options": {
            "TenantsEndpoint": "http://tenants-api:8080/api/tenants",
            "ForwardingAudience": "tenants-api"
          }
        }
      ]
    }
  }
}
```

AuthProxy refuses to start when signed forwarding is configured and no audience can be resolved for the
tenant-selection endpoint.

---

## Configuration

```json
{
  "Cratis": {
    "AuthProxy": {
      "ForwardingAttestation": {
        "Issuer": "https://auth.example.com",
        "ActiveKeyId": "forwarding-2026-10",
        "SigningKeys": [
          {
            "KeyId": "forwarding-2026-10",
            "PrivateKeyPem": "<from your secret provider>"
          }
        ],
        "Lifetime": "00:00:30"
      }
    }
  }
}
```

| Setting | Default | Description |
|---|---|---|
| `Issuer` | — | Written to `iss`. The verifying service must expect the same value. |
| `ActiveKeyId` | — | The key that signs new assertions, written to the `kid` header. Must identify exactly one entry in `SigningKeys`. |
| `SigningKeys` | `[]` | EC P-256 private keys, each with a `KeyId` and a PEM `PrivateKeyPem`. Key identifiers are case-sensitive and unique. |
| `Lifetime` | `00:00:30` | How long an assertion is valid. Between 10 and 60 seconds. |

Generate a key pair with OpenSSL:

```bash
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out forwarding-private.pem
openssl ec -in forwarding-private.pem -pubout -out forwarding-public.pem
```

Supply the private key through a secret provider; AuthProxy never logs or returns it. Give the verifying
services only the public key. There is no JWKS endpoint: each service pins the public keys it accepts and
selects one by `kid`.

Keys are read once at startup. Changing them requires a restart.

---

## Failure behavior

AuthProxy validates the section at startup and refuses to start when:

- `Issuer` or `ActiveKeyId` is empty, padded with whitespace or longer than allowed;
- a `KeyId` is missing, repeated or uses characters other than letters, digits, `.`, `_` and `-`, or
  `ActiveKeyId` matches no key;
- a `PrivateKeyPem` is missing or is not an EC P-256 private key;
- `Lifetime` is outside 10 to 60 seconds;
- no audience can be resolved for the tenant-selection endpoint.

Once signed forwarding is configured, AuthProxy **never forwards a request unsigned**. A proxied request it
cannot sign is answered with `502` and never reaches the service.

For its own calls, a signing failure counts as a failed call:

- the `/.cratis/me` call is not sent and is handled like an unreachable service under its
  `IdentityVerification` mode, so a `Required` service denies the request;
- the tenant-selection call is treated as unavailable, so the user gets `503` and no tenant cookie is written.

---

## Enabling it

Turn it on in this order, so no request is ever rejected for missing a signature:

1. **Upgrade both sides.** Upgrade AuthProxy, and upgrade the services to an Arc release that verifies
   forwarded identity ([Cratis/Arc#2837](https://github.com/Cratis/Arc/issues/2837)).
2. **Configure signing in AuthProxy.** A service that does not verify ignores the extra header, so nothing
   changes for it yet.
3. **Confirm the assertion arrives.** Check that requests reaching each service carry
   `x-cratis-forwarded-identity`.
4. **Configure verification in each service**, with the issuer, the audience and the public key.

Reversing the order makes every identity- or tenant-bearing request fail at the service until AuthProxy
signs.

---

## Rotating the key

1. **Publish the new public key** to every verifying service, next to the current one, and roll them out.
2. **Add the new private key** to `SigningKeys`, switch `ActiveKeyId` to it, and restart AuthProxy.
3. **Retire the old key** once every assertion signed with it has expired: wait at least `Lifetime` plus the
   clock-skew allowance the services verify with, then remove the old private key from AuthProxy and the
   old public key from the services.

---

## Relation to other signed messages

[Sign-in notifications](sign-in.md#the-signed-envelope) and invitation attestations are signed with the same
key model: a configured issuer, an active key identifier, and a set of private keys whose public halves the
receiver pins. The envelope is different: those are RS256 assertions over one message, while signed forwarding
is ES256 over every request. Use separate keys for each.
