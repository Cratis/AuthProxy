---
title: "Code Sign-in"
description: "Sign people in with a one-time code AuthProxy issues and verifies, while the application decides who is eligible and delivers the e-mail."
---

# Code Sign-in

A provider of type `Code` lets a person sign in by entering an e-mail address and then a short code. AuthProxy issues the
code, keeps only a salted hash of it, and verifies it. The application never sees a verified code and is never trusted to
say a code is right. What the application does own is who may sign in, the wording of the mail and its delivery.

Use it when the people who sign in are already known to the application and you do not want a second identity service
only to send codes. To use an external issuer such as Auth0 instead, see [E-mail Code Sign-in](email-code-sign-in.md).

---

## Configure the provider

```json
{
  "Cratis": {
    "AuthProxy": {
      "Authentication": {
        "CodeStatePath": "/var/lib/authproxy/code",
        "OidcProviders": [
          {
            "Name": "Code",
            "Type": "Code",
            "RequireVerifiedEmail": true,
            "DenialResponse": "FailedSignIn",
            "Session": { "Lifetime": "08:00:00", "SlidingExpiration": false },
            "CanonicalIdentity": { "ProviderKey": "code", "SubjectClaimType": "sub" },
            "Code": {
              "RequestUrl": "https://app.internal/_code/request",
              "Issuer": "https://app.example.com/.cratis/code",
              "Attestation": { "Issuer": "authproxy", "Audience": "app", "ActiveKeyId": "k1", "SigningKeys": [ { "KeyId": "k1", "PrivateKeyPem": "…" } ] },
              "CodeLength": 6,
              "Lifetime": "00:10:00",
              "MaxAttempts": 5,
              "Throttle": { "PerAddress": 3, "PerClient": 10, "Window": "00:10:00" }
            }
          }
        ]
      }
    }
  }
}
```

| Setting | Default | Description |
| --- | --- | --- |
| `Code:RequestUrl` | none | The application endpoint AuthProxy posts a signed request to. Required. |
| `Code:Issuer` | none | The issuer a [canonical identity](authentication.md#canonical-federated-identity) is attributed to: an absolute HTTPS address that never changes. It is part of the identity key, so every AuthProxy that should recognise the same people uses the same value. Required with `CanonicalIdentity`. |
| `Code:Attestation` | none | How the request to the application is signed: `Issuer`, `Audience`, `ActiveKeyId`, `SigningKeys` and `Lifetime` (10 to 60 seconds), as for [sign-in notifications](sign-in.md) but independent of them. Required. |
| `Code:CodeLength` | `6` | Digits in a code, 4 to 10. |
| `Code:Lifetime` | `00:10:00` | How long a code can be used, one minute to one hour. |
| `Code:MaxAttempts` | `5` | Wrong codes a challenge tolerates before it is destroyed, 1 to 10. |
| `Code:Throttle` | 3 per address, 10 per client, per 10 minutes | Limits on requesting codes. They are counted before the application is called. |
| `CodeStatePath` | a directory under the temp path | Where in-flight challenges and request counters live. |

`Code:Attestation` is how the application tells that AuthProxy is the one asking it to send a code.
`RequireVerifiedEmail`, `DenialResponse`, `Session` and `CanonicalIdentity` work as for any other provider: a
person who enters a code has proven they can read the address, so the principal carries `sub`, `email` and
`email_verified: true`, and the [shorter session](authentication.md#per-provider-browser-session-lifetime) and
[fresh authentication](fresh-authentication.md) rules apply as usual.

## The flow

1. `/.cratis/login/{scheme}` redirects to `/signin-{scheme}` with the protected sign-in state. Everything after that
   happens on that one path.
2. The **address page** (`code-email.html`) asks for an e-mail address. When the sign-in answers an invitation whose
   capability carries an address (`Invite:EmailClaim`), the page shows that address locked and the person only presses
   send; an address typed into a bound invitation is ignored.
3. AuthProxy creates a challenge and asks the application to deliver the code (below).
4. The **code page** (`code-verify.html`) asks for the code. A right code consumes the challenge and signs the person in
   through the same pipeline as any provider, including invitation completion and sign-in notification. A wrong code
   counts an attempt; at `MaxAttempts` the challenge is destroyed.

Both pages are [well-known pages](well-known-pages.md) and can be replaced like the others.

## The request to the application

AuthProxy posts JSON to `Code:RequestUrl`:

```json
{ "email": "ada@example.com", "code": "482913", "purpose": "signIn", "invitationId": null, "locale": "nb-NO", "expiresAt": "2026-11-20T10:10:00+00:00" }
```

`purpose` is `signIn`, or `invitation` when the sign-in answers an invitation (with `invitationId`). The request carries a
bearer attestation signed with the `Code:Attestation` key, with the claims `purpose` = `code-request`, `htm`, `htu`,
`body_hash` and the usual `iss`, `aud`, `exp` and `jti`. **The application must check that `purpose` is `code-request`**:
an attestation made for any other purpose, such as a sign-in notification, must never be accepted here.

The application answers `200` with `{ "subject": "<stable id>" }` when it accepts the address and has sent the mail, and
`200 {}` (or any other answer) when it does not. The subject becomes the `sub` of the session; use an identifier that never
changes, not the address. The application owns the mail text and delivery, and must never log the code.

## Not telling who has an account

The browser gets the same code page and an equivalent challenge whether the application accepted the address or not. A
challenge for an address the application refused carries no subject and is counted like any other, so a wrong code and a
code for an unknown address cannot be told apart. A request over the throttle limit also looks the same; it simply is not
passed on. Keep the application's own answer time even where you can, since AuthProxy cannot hide it.

## Challenge state on a volume

Challenges are small files in `CodeStatePath`: the address, the subject, the salt and hash of the code, the expiry and the
attempt count, never the code. Mount a volume there so challenges survive a restart; with several replicas mount a shared
ReadWriteMany volume. Reads and writes open the file exclusively, so a code is consumed at most once and attempts are
counted exactly even when requests race. Old files are swept.

A six-digit code is small. The salted hash only protects against casual reading of the volume; the attempt limit and the
throttle are what protect the code, so keep the volume private to AuthProxy.
