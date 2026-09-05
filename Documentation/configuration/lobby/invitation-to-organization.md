# Invitation to Organization

Use this flow when you invite a user into an organization that already exists. AuthProxy still uses
the standard `/invite/<token>` bootstrap, but a matching invitation tenant claim and the `ReturnUrl`
destination let the user continue directly into the application instead of being sent to Lobby.

## Flow

1. The user opens `https://your-authproxy/invite/<token>`.
2. AuthProxy validates the token, creates an independent 256-bit transaction and challenge, and calls
   `Invite.StageUrl`. The signed `invite-stage` attestation binds those values to the exact capability hash,
   invitation ID, and tenant before provider authentication starts.
3. AuthProxy protects the pending state in an HTTP-only cookie and binds it into the provider's protected
   challenge state. A browser can carry the values but cannot author or substitute them.
4. After login, AuthProxy **re-validates the token** (signature, issuer, audience, and lifetime), the protected
   pending state, and the provider challenge binding.
5. AuthProxy requires one canonical provider identity, one provider-derived email with an exact verified value
   of `true`, one provider-derived assurance value, and the authentication-ticket issue time.
6. AuthProxy calls `Invite.ExchangeUrl` with a signed `invite-complete` attestation. The JSON body contains only
   the opaque transaction ID; the browser and request body never supply identity authority.
7. AuthProxy compares the configured `Invite.TenantClaim` from the token with the tenant resolved for the request.
   Equality is observational routing evidence, not issuer identity: it does not prove which tenant issued the
   invitation.
8. If the tenant values match, `Invite.MatchingTenantInvitationDestination` selects `ReturnUrl` or `Lobby`.
   `ReturnUrl` is the default and continues to the target service.

If the tenant values differ, or AuthProxy cannot observe both values, the invitation selects Lobby when its frontend
is configured. The matching-tenant enum does not change those rows of the shared routing matrix.

## Configuration

```json
{
  "Cratis": {
    "AuthProxy": {
      "Invite": {
        "StageUrl": "https://lobby.example.com/_invite/stage",
        "ExchangeUrl": "https://lobby.example.com/_invite/exchange",
        "TenantClaim": "tenant_id",
        "MatchingTenantInvitationDestination": "ReturnUrl",
        "EmailClaim": "email",
        "Attestation": {
          "Issuer": "https://auth.example.com",
          "Audience": "ada-lobby",
          "ActiveKeyId": "invite-2026-08",
          "Lifetime": "00:01:00",
          "SigningKeys": [
            {
              "KeyId": "invite-2026-08",
              "PrivateKeyPem": "<load-from-secret-provider>"
            }
          ]
        },
        "Lobby": {
          "Frontend": { "BaseUrl": "http://lobby-service:3000/" }
        }
      }
    }
  }
}
```

| Property | Type | Description |
|----------|------|-------------|
| `StageUrl` | `string` | Absolute URL of the Lobby invitation authority's pre-authentication staging endpoint. Required when `Attestation` is configured. |
| `ExchangeUrl` | `string` | Absolute URL of the same Lobby invitation authority's completion endpoint. |
| `TenantClaim` | `string` | Claim in the invite token that contains the tenant ID observed for routing. Equality with the resolved tenant does not identify the invitation issuer. |
| `MatchingTenantInvitationDestination` | `InvitationCompletionDestination` | Destination for matching tenant values. `ReturnUrl` is the default; use `Lobby` to select `Lobby.Frontend.BaseUrl`. |
| `EmailClaim` | `string` | Claim in the invite token that contains the invited email. Required by the signed protocol. |
| `Attestation.Issuer` | `string` | Exact issuer the invitation authority validates. |
| `Attestation.Audience` | `string` | Exact invitation-authority audience. |
| `Attestation.ActiveKeyId` | `string` | Key ID used for newly signed attestations. |
| `Attestation.SigningKeys` | `array` | RSA private signing keys. Load private PEM values from a secret provider; pin only the matching public keys downstream. |
| `Attestation.Lifetime` | `TimeSpan` | Short-lived token lifetime from 10 through 60 seconds. Defaults to 60 seconds. |
| `Lobby.Frontend.BaseUrl` | `string` | Fallback redirect if the invite cannot continue directly into the organization. |

## Signed protocol

The staging call uses `Authorization: Bearer <stage-attestation>` and this bounded body:

```json
{
  "invitationTransaction": "<opaque transaction>",
  "invitationToken": "<exact signed invitation capability>",
  "invitationChallenge": "<independent opaque challenge>"
}
```

The completion call uses `Authorization: Bearer <complete-attestation>` and a body with no identity fields:

```json
{
  "invitationTransaction": "<opaque transaction>"
}
```

Both RS256 JWTs require `kid`, `iss`, `aud`, `jti`, `iat`, `nbf`, and `exp`. They bind `purpose`, `tenant_id`,
`invitation_id`, `invitation_transaction`, `invitation_challenge`, and `capability_hash`. Every completion
attestation additionally carries `provider_key`, `provider_issuer`, `provider_subject`, `assurance`, and
`authenticated_at`. Email-targeted completion also carries `email` and `email_verified=true`.

The same Lobby invitation authority owns both endpoints. It must independently validate the raw invitation during staging, compare its exact SHA-256
hash to `capability_hash`, persist no raw capability, and atomically consume the transaction and complete-attestation
`jti` exactly once. It must reject a wrong purpose, signature, key ID, issuer, audience, lifetime, tenant,
invitation, transaction, challenge, or capability hash.

Configure [canonical federated identity](../authentication.md#canonical-federated-identity) for every provider.
The selected email, verification, and assurance claim types must name provider-derived claims. Missing, duplicate,
empty, unverified, or ambiguous evidence fails closed before the completion endpoint is called.
Set `CanonicalIdentity.InvitationCompletionEnabled=true` only for providers that can supply that evidence. Signed
invitation provider selection hides every other provider while leaving it available for ordinary sign-in. Microsoft
Entra commonly omits `email_verified`; do not enable it unless the tenant maps an equivalent trustworthy custom
claim and configures its exact claim type. AuthProxy never promotes `email` or `preferred_username` to verified
evidence implicitly.

Every signed invitation must select exactly one recipient-authority mode: either one nonempty invited-email claim,
or the exact immutable provider-binding pair below. Missing, duplicate, partial, or mixed recipient claims are
rejected before staging and again before completion.

For a recipient already known by immutable provider identity, the signed invitation may carry both
`recipient_provider_key` and `recipient_identity_binding`. The binding is a canonical 43-character base64url
HMAC-SHA-256 value over the provider key, tenant-specific validated issuer, and immutable provider subject using
the invitation authority's documented length-delimited input format. AuthProxy validates the claim shape, restricts
the chooser and callback to the exact provider key, and emits the provider key, validated issuer, subject,
assurance, and authentication time without inventing email evidence. The invitation authority remains responsible
for independently recomputing the opaque binding and comparing it to the staged capability before atomic
consumption. Enable this route with
`CanonicalIdentity.InvitationIdentityBindingCompletionEnabled=true`; email-targeted invitations continue to require
`InvitationCompletionEnabled=true` and exact verified-email evidence.

For Microsoft Entra identity-bound invitations, configure a tenant-specific authority and
`CanonicalIdentity.SubjectClaimType=oid`. The framework-validated tenant issuer plus immutable object ID is the
identity tuple; `email` and `preferred_username` are not substitutes.

> **Compatibility.** Omitting `Invite.Attestation` retains the released unsigned JSON exchange for existing
> deployments. That legacy mode is not sufficient authority for creating or linking an account. Enable the signed
> protocol before an application treats invitation completion as identity proof. Independently,
> `Invite.MatchingTenantInvitationDestination` defaults to `ReturnUrl`, preserving the released matching-tenant
> redirect behavior.

## Rotate signing keys

1. Add the new public key to the invitation authority's pinned verification set.
2. Add the new private key and key ID to `SigningKeys` without changing `ActiveKeyId`.
3. Deploy both sides, then switch `ActiveKeyId`.
4. Keep the previous public key until every token it signed has expired, then remove the old key from both sides.

AuthProxy selects exactly one active key and always writes its `kid`. It never logs private key material or
attestation payloads.

## Requirements

- The invite token must include the claim configured in `Invite.TenantClaim`.
- The request must resolve to the same tenant value after authentication.
- The invitation link should use the same host and route shape that the organization's normal
  traffic uses so tenant resolution produces the expected value.

## When to use another flow

- If the invited user should create a new organization, use
  [Invitation for Creating Organization](invitation-for-creating-organization.md).
- If the user should self-register and create an organization without an invite, use
  [Registration](registration.md).
