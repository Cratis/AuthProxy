# Registration

Use registration when a user should create a new organization without receiving an invite first.
Users who are joining an existing organization should use an invitation flow instead.

## Flow

1. The user opens `https://your-authproxy/register`.
2. AuthProxy stores a short-lived HTTP-only registration cookie.
3. AuthProxy starts authentication.
   - With one configured identity provider, AuthProxy challenges that provider directly.
   - With multiple providers, AuthProxy redirects to the standard login page so the user can choose
     a provider.
4. After a successful login, AuthProxy deletes the registration cookie.
5. AuthProxy redirects the user to `Invite.Lobby.Registration.BaseUrl`.

The `/register` path is only active when `Invite.Lobby.Registration.BaseUrl` is configured.

## Configuration

```json
{
  "Cratis": {
    "AuthProxy": {
      "Invite": {
        "Lobby": {
          "Registration": { "BaseUrl": "https://lobby.example.com/register" }
        }
      }
    }
  }
}
```

| Property | Type | Description |
|----------|------|-------------|
| `Lobby.Registration.BaseUrl` | `string` | Absolute URL for the lobby registration experience that creates the organization after AuthProxy sign-in. |

## Aspire

When you configure AuthProxy through Aspire, set the registration destination with
`WithLobbyRegistration(...)`:

```csharp
authproxy.WithLobbyRegistration(lobbyResource, "/register");

// or use a raw URL
authproxy.WithLobbyRegistration("https://lobby.example.com/register");
```

This sets `Cratis:AuthProxy:Invite:Lobby:Registration:BaseUrl`.
