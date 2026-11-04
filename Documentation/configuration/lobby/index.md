---
title: "Lobby"
description: "The AuthProxy lobby finishes onboarding for users who cannot enter the application directly, through invitations or self-serve registration."
---

# Lobby

AuthProxy uses the lobby to finish onboarding when a user cannot enter the application directly
after authentication.

Choose the route based on what the user needs to do after signing in:

- [Registration](registration.md) — let a user create an organization without receiving an invitation.
- [Invitation to Organization](invitation-to-organization.md) — invite a user directly into an
  existing organization. Use an invitation, not registration, when the user should join an organization.
- [Invitation for Creating Organization](invitation-for-creating-organization.md) — invite a user
  who should create a new organization after they sign in.

Registration needs a destination for the registration experience. The two invitation routes share
additional setup: AuthProxy must verify the incoming invitation, authenticate its recipient, and complete
it with the Lobby invitation authority before choosing the destination.

For incoming invitation verification, a pinned public key and metadata-based keys are alternatives.
[Invitation token keys](invitation-token-keys.md) explains the metadata option, including its version,
issuer, audience, and retrieval requirements. These verification keys are separate from the private keys
under `Invite.Attestation`, which AuthProxy uses to sign outgoing staging and completion calls. The same
Lobby invitation authority must own both endpoints and validate those attestations.

Before configuring either invitation route, also configure the recipient mode and eligible identity
providers. The shared [Signed protocol](invitation-to-organization.md#signed-protocol) reference gives
those prerequisites, the authority's responsibilities, and the exact protocol. The individual guides
show the settings for the destination you chose.

## Shared invitation routing

After successful invitation completion, a matching tenant can continue to the application or go to Lobby;
nonmatching or unresolved tenants go to the configured Lobby frontend, or otherwise to the return URL.

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

`Lobby` provides destination settings, not all settings available to a proxy [`Service`](../services.md).
Proxy clusters come from `Services`, not `Lobby`. AuthProxy rejects `ActivityTimeout` on Lobby or its
`Backend`, `Frontend`, and `Registration` endpoints.

Configure the Lobby destinations under `Cratis:AuthProxy:Invite:Lobby`:

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
