---
title: "E-mail Code Sign-in"
description: "Admit people who sign in with an e-mailed one-time code through an OpenID Connect provider such as Auth0, refusing unverified addresses and unknown identities."
---

# E-mail Code Sign-in

An OpenID Connect provider can offer a passwordless e-mail code as one way to sign in. That proves less than a
federated sign-in with a workforce account: the provider only vouches that the person could read a message sent
to one address. This recipe admits such people safely by combining three provider settings with a check in the
application.

---

## Configure the provider

```json
{
  "Cratis": {
    "AuthProxy": {
      "Authentication": {
        "OidcProviders": [
          {
            "Name": "Auth0",
            "Authority": "https://tenant.example.auth0.com",
            "ClientId": "client-id",
            "AuthorizationParameters": { "connection": "email" },
            "RequireVerifiedEmail": true,
            "DenialResponse": "FailedSignIn",
            "Session": { "Lifetime": "00:30:00", "SlidingExpiration": false }
          }
        ]
      }
    }
  }
}
```

- `AuthorizationParameters` asks the provider for its e-mail connection directly.
- `RequireVerifiedEmail` refuses a callback unless the principal has exactly one e-mail address that the provider
  reports as verified. Nothing is signed in, and the person lands on provider selection with
  `reason=remote-failure`.
- `DenialResponse` makes an identity denial look the same as that failure, so a probe cannot learn whether an
  address is recognized.
- A short per-provider `Session` lifetime limits how long a code-based session lasts. See
  [Per-provider browser session lifetime](authentication.md#per-provider-browser-session-lifetime).

See [Gating a weaker provider](authentication.md#gating-a-weaker-provider) for the exact rules of each setting.

## Decide who may enter in the application

AuthProxy does not know which verified addresses your application accepts. Configure
[identity enrichment](services.md#identity-enrichment) so the application answers for each signed-in person, and let it refuse
addresses it does not know. Set `Session:TerminateOnIdentityDenial` for providers that keep the default
`DenialResponse`; a provider set to `FailedSignIn` always ends the session on a denial.

## What to expect

A person whose address the application refuses still holds a session until their first proxied request, because
the identity details are consulted per request. That request ends the session and sends a navigating browser to
provider selection, exactly as a failed sign-in would.
