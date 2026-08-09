# Invitation to Organization

Use this flow when you invite a user into an organization that already exists. AuthProxy still uses
the standard `/invite/<token>` bootstrap, but the invite token carries tenant information so the
user can continue directly into the application instead of being sent to the lobby.

## Flow

1. The user opens `https://your-authproxy/invite/<token>`.
2. AuthProxy validates the token and starts authentication in the same way as any other invite.
3. After login, AuthProxy **re-validates the token** (signature, issuer, audience, and lifetime) before
   forwarding it, so AuthProxy is the authoritative validator across both phases.
4. If `Invite.EmailClaim` is configured (opt-in) and the token carries that claim, AuthProxy binds the
   invite to its recipient using provider-supplied authenticated-session email evidence. If the provider
   supplies no address, AuthProxy serves `invitation-email-unavailable.html`. If it supplies another address,
   or explicitly reports `email_verified=false`, AuthProxy serves `invitation-email-mismatch.html`.
5. AuthProxy exchanges the invite at `Invite.ExchangeUrl`, always forwarding the provider-supplied address and
   any `email_verified` value so the backend can apply its own binding check — whether or not gateway
   enforcement is on.
6. AuthProxy compares the configured `Invite.TenantClaim` from the token with the resolved tenant
   for the request.
7. If the tenant IDs match, AuthProxy skips the lobby redirect and continues to the target service.

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
        "EmailClaim": "email",
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
| `EmailClaim` | `string` | Claim in the invite token that contains the email the invitation was issued for. **Empty by default, which leaves gateway email-binding enforcement off.** Set it (for example to `email`) to require provider-supplied authenticated-session email evidence to match the invited email at the exchange. The email and any provider-supplied `email_verified` value are forwarded regardless of this setting. |
| `Lobby.Frontend.BaseUrl` | `string` | Fallback redirect if the invite cannot continue directly into the organization. |

## Exchange request body

Providers without [canonical federated identity](../authentication.md#canonical-federated-identity) keep the
legacy request body:

```json
{
  "subject": "<provider subject>",
  "identityProvider": "<issuer / provider>",
  "email": "<provider-supplied address or empty string>",
  "emailVerified": null
}
```

Canonical providers send:

```json
{
  "subject": "<configured canonical subject>",
  "providerKey": "<configured stable provider key>",
  "issuer": "<normalized validated or configured issuer>",
  "identityProvider": "<same value as providerKey>",
  "email": "<provider-supplied address or empty string>",
  "emailVerified": null
}
```

`emailVerified` is a JSON boolean when the provider supplies a parseable value; otherwise it is `null` as
shown above.

Canonical identity is opt-in per provider, so the exchange endpoint must accept both shapes during migration.
For canonical providers, bind the account with all three `(providerKey, issuer, subject)` components. A
successful provider sign-in and invite exchange does not decide application membership, roles, or authorization;
the application owns those decisions.

The `email_verified` value is provider-supplied evidence, not a universal guarantee. AuthProxy rejects an
explicit `false`, but an absent claim becomes `null` and does not independently prove address ownership.
OAuth providers do not currently map `email_verified`, so their address is forwarded with `null`. If a provider
does not supply an address at all, the unavailable page is used rather than misreporting a mismatch.

> **Security.** The signed invitation remains the bearer credential, but this JSON body is not itself signed.
> Keep `Invite.ExchangeUrl` network-isolated from public traffic or authenticate AuthProxy separately, and
> validate the invitation token at the application boundary before trusting invite claims.

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
