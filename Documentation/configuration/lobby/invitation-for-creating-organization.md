# Invitation for Creating Organization

Use this flow when you invite a user who should create a new organization after they authenticate.
AuthProxy validates the invite, exchanges it after sign-in, and then sends the user to the lobby
frontend to finish onboarding.

## Flow

1. The user opens `https://your-authproxy/invite/<token>`.
2. AuthProxy validates the signed JWT invite token.
3. If the token is valid, AuthProxy stores it in a short-lived HTTP-only cookie.
   - With one configured identity provider, AuthProxy challenges that provider immediately.
   - With multiple providers, AuthProxy serves `invitation-select-provider.html` so the user can
     choose how to sign in.
4. After a successful login, AuthProxy re-validates the token, then calls `Invite.ExchangeUrl` with the
   invite token and the authenticated user's subject and verified email.
   - The token is re-validated (signature, issuer, audience, lifetime) before it is forwarded.
   - If gateway email binding is enabled (`Invite.EmailClaim` is set) and the token was issued for a
     specific email, the account's verified email must match, otherwise `invitation-email-mismatch.html`
     is served.
5. If the exchange succeeds, AuthProxy redirects the user to `Invite.Lobby.Frontend.BaseUrl`.

This flow is the right fit when the invited user is not entering an already-resolved tenant.

## Configuration

```json
{
  "Cratis": {
    "AuthProxy": {
      "Invite": {
        "PublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
        "Issuer": "https://studio.example.com",
        "Audience": "authproxy",
        "ExchangeUrl": "https://studio.example.com/internal/invites/exchange",
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
| `ExchangeUrl` | `string` | Absolute URL of the invite exchange endpoint. |
| `SubjectAlreadyExistsUrl` | `string` | Redirect target when the exchange endpoint returns HTTP 409. Leave empty to serve `invitation-subject-already-exists.html`. |
| `AppendInvitationIdToQueryString` | `bool` | Appends `jti` from the invite token to the lobby redirect URL when enabled. |
| `InvitationIdQueryStringKey` | `string` | Query-string key used when appending the invitation ID. |
| `ClaimsToForward` | `InviteClaimForwarding[]` | Claim mappings forwarded from the invite token into the identity details request. |
| `Lobby.Frontend.BaseUrl` | `string` | Lobby URL used after a successful invite exchange. |

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
| `sub` | Subject for the invited user. AuthProxy includes it in the exchange call. |

## Error handling

AuthProxy serves dedicated pages for each invitation error:

| Page file | Condition | HTTP status |
|-----------|-----------|-------------|
| `invitation-expired.html` | The token signature is valid, but the `exp` claim is in the past. | 401 |
| `invitation-invalid.html` | The token is malformed or has an invalid signature. | 401 |
| `invitation-select-provider.html` | The token is valid and multiple identity providers are configured. | 200 |
| `invitation-subject-already-exists.html` | The authenticated subject is already associated with an existing account. | 409 |

See [Error pages](../error-pages.md) for customization details and
[Custom Invitation Provider-Selection Page](../invitation-provider-selection.md) for a full branded
provider-selection walkthrough.
