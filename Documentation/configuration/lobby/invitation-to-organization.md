# Invitation to Organization

Use this flow when you invite a user into an organization that already exists. AuthProxy still uses
the standard `/invite/<token>` bootstrap, but the invite token carries tenant information so the
user can continue directly into the application instead of being sent to the lobby.

## Flow

1. The user opens `https://your-authproxy/invite/<token>`.
2. AuthProxy validates the token and starts authentication in the same way as any other invite.
3. After login, AuthProxy exchanges the invite at `Invite.ExchangeUrl`.
4. AuthProxy compares the configured `Invite.TenantClaim` from the token with the resolved tenant
   for the request.
5. If the tenant IDs match, AuthProxy skips the lobby redirect and continues to the target service.

If the tenant IDs do not match, or AuthProxy cannot resolve a tenant for the request, the invite is
treated like lobby onboarding and falls back to the configured lobby behavior.

## Configuration

```json
{
  "Cratis": {
    "AuthProxy": {
      "Invite": {
        "ExchangeUrl": "https://studio.example.com/internal/invites/exchange",
        "TenantClaim": "tenant_id",
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
| `ExchangeUrl` | `string` | Absolute URL of the invite exchange endpoint. |
| `TenantClaim` | `string` | Claim in the invite token that contains the tenant ID. |
| `Lobby.Frontend.BaseUrl` | `string` | Fallback redirect if the invite cannot continue directly into the organization. |

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
