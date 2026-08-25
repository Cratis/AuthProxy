# Lobby

AuthProxy uses the lobby to finish onboarding when a user cannot enter the application directly
after authentication.

Use the lobby documentation based on the onboarding outcome you need:

- [Invitation for Creating Organization](invitation-for-creating-organization.md) — invite a user
  who should create a new organization after they sign in.
- [Invitation to Organization](invitation-to-organization.md) — invite a user directly into an
  existing organization.
- [Registration](registration.md) — let a user start a self-serve registration flow that ends in
  organization creation. If the user should join an existing organization, invite them instead.

## Shared invitation routing

AuthProxy compares the validated invitation's configured `TenantClaim` value with the tenant resolved for the
request. That equality is observational routing evidence, not issuer identity: it proves only that both observed
values are equal. It does not prove which tenant issued the invitation, because any authority holding the invitation
signing key can write the claim.

| Observed tenant relation | `MatchingTenantInvitationDestination` | Successful completion destination |
|--------------------------|---------------------------------------|-----------------------------------|
| Matching | `ReturnUrl` (default) | The invitation challenge's return URL. |
| Matching | `Lobby` | `Lobby.Frontend.BaseUrl`, with the invitation ID query parameter when enabled. |
| Nonmatching | Either value | `Lobby.Frontend.BaseUrl` when configured; otherwise the return URL. |
| Unresolved | Either value | `Lobby.Frontend.BaseUrl` when configured; otherwise the return URL. |

The destination setting changes only the matching row. It does not change validation, staging, exchange, recipient
binding, attestations, transaction consumption, cookies, or sessions.

## Shared configuration

All lobby-related settings live under `Cratis:AuthProxy:Invite:Lobby`:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Invite": {
        "Lobby": {
          "Frontend": { "BaseUrl": "http://lobby-service:3000/" },
          "Backend": { "BaseUrl": "http://lobby-service:8080/" },
          "Registration": { "BaseUrl": "http://lobby-service:3000/register" }
        }
      }
    }
  }
}
```

The `Lobby` object uses the standard [`Service`](../services.md) shape.

| Property | Type | Description |
|----------|------|-------------|
| `Frontend.BaseUrl` | `string` | URL used for lobby redirects after onboarding or when tenant resolution fails. |
| `Backend.BaseUrl` | `string` | Optional backend API URL for the lobby service. |
| `Registration.BaseUrl` | `string` | Optional URL used after `GET /register` completes successfully. |

## Lobby fallback

Tenant resolution runs before invite and registration handling.

When AuthProxy cannot resolve a tenant and a lobby frontend is configured, it redirects the user to
`Lobby.Frontend.BaseUrl` unless the request is already an onboarding bootstrap path such as
`/invite/<token>` or `/register`.
