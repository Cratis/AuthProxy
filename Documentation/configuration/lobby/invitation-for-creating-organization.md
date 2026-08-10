# Invitation for Creating Organization

Use this flow when you invite a user who should create a new organization after they authenticate.
AuthProxy validates and stages the invite with the Lobby invitation authority, authenticates the recipient,
completes the staged transaction with a signed attestation, and then sends the user to the Lobby frontend.

## Flow

1. The user opens `https://your-authproxy/invite/<token>`.
2. AuthProxy validates the signed JWT invite token.
3. AuthProxy generates an independent transaction and challenge, signs an `invite-stage` attestation, and calls
   `Invite.StageUrl`. The Lobby invitation authority validates the exact capability, persists only its hash and
   bounded transaction state, and discards the raw token.
4. AuthProxy protects the staged state and invite token in short-lived HTTP-only cookies.
   - With one configured identity provider, AuthProxy challenges that provider immediately.
   - With multiple providers, AuthProxy serves `invitation-select-provider.html` so the user can
     choose how to sign in.
5. After successful provider authentication, AuthProxy re-validates the token and protected transaction bindings,
   derives canonical provider identity from the authenticated ticket, and calls `Invite.ExchangeUrl` with a signed
   `invite-complete` attestation. The JSON body contains only the opaque transaction ID.
6. The same Lobby invitation authority verifies and atomically consumes the transaction and attestation ID. If it
   succeeds, AuthProxy redirects the user to `Invite.Lobby.Frontend.BaseUrl`.

This flow is the right fit when the invited user is not entering an already-resolved tenant.

## Configuration

```json
{
  "Cratis": {
    "AuthProxy": {
      "Invite": {
        "PublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
        "Issuer": "https://ada.example.com",
        "Audience": "authproxy",
        "StageUrl": "https://lobby.example.com/_invite/stage",
        "ExchangeUrl": "https://lobby.example.com/_invite/exchange",
        "TenantClaim": "tenant_id",
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
        "SubjectAlreadyExistsUrl": "https://app.example.com/errors/account-already-exists",
        "AppendInvitationIdToQueryString": true,
        "InvitationIdQueryStringKey": "invitationId",
        "ClaimsToForward": [
          { "FromClaimType": "organization_id", "ToClaimType": "organization" },
          { "FromClaimType": "invited_by" }
        ],
        "Lobby": {
          "Frontend": { "BaseUrl": "http://lobby-service:3000/" },
          "Backend": { "BaseUrl": "http://lobby-service:8080/" }
        }
      }
    }
  }
}
```

| Property | Type | Description |
|----------|------|-------------|
| `PublicKeyPem` | `string` | PEM-encoded RSA public key used to verify invite token signatures. |
| `Issuer` | `string` | Expected `iss` claim. Leave empty to skip issuer validation. |
| `Audience` | `string` | Expected `aud` claim. Leave empty to skip audience validation. |
| `StageUrl` | `string` | Absolute URL of the Lobby invitation authority's staging endpoint. |
| `ExchangeUrl` | `string` | Absolute URL of the same Lobby invitation authority's completion endpoint. |
| `TenantClaim` | `string` | Claim containing the tenant that owns the invitation. Required by the signed protocol. |
| `EmailClaim` | `string` | Claim type used by the exclusive email-recipient mode. The signed capability must contain exactly one value of this claim or the immutable provider-binding pair, never both. |
| `Attestation` | `object` | RS256 issuer, audience, active key, private signing-key set, and 10–60-second lifetime used for the two internal calls. |
| `SubjectAlreadyExistsUrl` | `string` | Redirect target when the exchange endpoint returns HTTP 409. Leave empty to serve `invitation-subject-already-exists.html`. |
| `AppendInvitationIdToQueryString` | `bool` | Appends `jti` from the invite token to the lobby redirect URL when enabled. |
| `InvitationIdQueryStringKey` | `string` | Query-string key used when appending the invitation ID. |
| `ClaimsToForward` | `InviteClaimForwarding[]` | Claim mappings forwarded from the invite token into the identity details request. |
| `Lobby.Frontend.BaseUrl` | `string` | Lobby URL used after a successful invite exchange. |

## Signed protocol

Creating-organization and existing-organization invitations use the same signed two-stage Lobby protocol. See
[Signed protocol](invitation-to-organization.md#signed-protocol) for the exact stage and completion bodies,
attestation claims, exclusive recipient modes, verification rules, key rotation, and compatibility contract.

The browser never authors provider identity. Both internal calls are authenticated by short-lived AuthProxy
attestations, and the completion body contains no email, provider, issuer, or subject fields.

> **Legacy compatibility.** Omitting `Invite.Attestation` retains the released unsigned JSON exchange. That mode is
> not sufficient authority for creating or linking an account and must not be used for production onboarding.

## Invite claim forwarding

When `ClaimsToForward` is configured and a pending invite cookie exists, AuthProxy reads the
configured invite-token claims and adds them to the principal payload sent to each `/.cratis/me`
identity details endpoint.

- Existing identity-provider claims are preserved.
- Mapped invite claims are appended if present.
- If `ToClaimType` is empty, AuthProxy uses `FromClaimType`.

## Invite token format

Invite tokens are JWTs signed with an RSA private key held by the issuing service. AuthProxy only
needs the matching public key to validate the signature.

Recommended claims:

| Claim | Description |
|-------|-------------|
| `iss` | Issuer. Must match `Invite.Issuer` when configured. |
| `aud` | Audience. Must match `Invite.Audience` when configured. |
| `exp` | Expiry time. Expired tokens are rejected. |
| `jti` | Unique invitation identifier. Required by the signed protocol. |
| `tenant_id` | Tenant that owns the invitation, using the configured `TenantClaim` name. |
| `email` | Exactly one invited address for email-recipient mode, using the configured `EmailClaim` name. |
| `recipient_provider_key` + `recipient_identity_binding` | Exact provider key and 43-character opaque binding for immutable identity mode. Both are required together and `email` must be absent. |

## Error handling

AuthProxy serves dedicated pages for each invitation error:

| Page file | Condition | HTTP status |
|-----------|-----------|-------------|
| `invitation-expired.html` | The token signature is valid, but the `exp` claim is in the past. | 401 |
| `invitation-invalid.html` | The token is malformed or has an invalid signature. | 401 |
| `invitation-select-provider.html` | The token is valid and multiple identity providers are configured. | 200 |
| `invitation-subject-already-exists.html` | The authenticated subject is already associated with an existing account. | 409 |
| `invitation-email-unavailable.html` | Legacy unsigned mode only: email binding is enabled, but the provider supplied no authenticated-session address. | 403 |
| `invitation-email-mismatch.html` | Legacy unsigned mode only: email binding is enabled, and the provider supplied another address or explicitly reported `email_verified=false`. | 403 |

See [Error pages](../error-pages.md) for customization details and
[Custom Invitation Provider-Selection Page](../invitation-provider-selection.md) for a full branded
provider-selection walkthrough.
