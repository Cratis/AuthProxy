---
title: "Application configuration contract"
description: "Start AuthProxy from a Screenplay model's provider list and the values of a Cratis environment: the provider kinds, the environment keys, how secrets are read, and the invitation settings for an application's Ante."
---

# Application configuration contract

AuthProxy can start from two inputs and nothing else:

1. **The provider list** of an application's Screenplay model: for each provider its kind and its identity.
2. **The values of a Cratis environment**: authorities, client ids, client secrets and, when the application has
   onboarding, the settings of its Ante.

`cratis run` and Showrunner's Stage Manager both produce exactly this contract. AuthProxy translates it onto its
ordinary [`Cratis:AuthProxy`](index.md) options at startup, so everything else behaves as if you had written those
options yourself. The contract is additive: a deployment that does not set `Cratis:AuthProxy:Application` is unchanged.

A shared fixture with placeholder values lives in the repository's
[`Contract`](https://github.com/Cratis/AuthProxy/tree/main/Contract) folder in JSON and environment-variable form.
The specifications bind both against every provider kind, so a producer can test against the same files.

## The provider list

```json
{
  "Cratis": {
    "AuthProxy": {
      "Application": {
        "EnvironmentName": "development",
        "Providers": [
          { "Kind": "EntraId", "Identity": "EntraId" },
          { "Kind": "OpenId", "Identity": "Partner" }
        ]
      }
    }
  }
}
```

| Key | Description |
| --- | --- |
| `Cratis:AuthProxy:Application:Providers:<n>:Kind` | `EntraId`, `GitHub`, `Google`, `Apple` or `OpenId` (case-insensitive). |
| `Cratis:AuthProxy:Application:Providers:<n>:Identity` | The model's alias, otherwise the provider name. Two `OpenId` providers differ by alias. Letters, digits, spaces, hyphens and underscores; unique ignoring case. |
| `Cratis:AuthProxy:Application:EnvironmentName` | Optional. The Cratis environment's name, used in messages. |
| `Cratis:AuthProxy:Application:Onboarding` | `true` when the application has onboarding. See [Onboarding](#onboarding). |
| `Cratis:AuthProxy:Application:Development` | `true` to allow HTTP on loopback addresses. See [Development](#development). |
| `Cratis:AuthProxy:Application:SecretsDirectory` | Optional. A directory holding one file per environment key. See [Secrets](#secrets). |

The identity is the provider's display name on the sign-in page and its authentication scheme (lowercase, spaces
become hyphens), so the provider calls back on `/signin-<scheme>`.

The provider list cannot be combined with providers configured directly under
`Cratis:AuthProxy:Authentication:OidcProviders` or `OAuthProviders`: AuthProxy refuses to start and says so.

## Environment keys

Each value is addressed by the key the Cratis environment uses:
`authentication.providers.<Identity>.<key>`, and `onboarding.<key>`. The keys are looked up in
[these places](#secrets). In `appsettings.json` they sit under `Cratis:AuthProxy:Application:Environment`, as
property names with dots; as environment variables they are
`Cratis__AuthProxy__Application__Environment__authentication.providers.EntraId.clientId`.

### Provider kinds

| Kind | Mapped onto | Required keys | Optional keys |
| --- | --- | --- | --- |
| `EntraId` | OIDC, brand `Microsoft` | `tenantId`, `clientId`, `clientSecret` | `authority` (replaces `https://login.microsoftonline.com/<tenantId>/v2.0`), `scopes`, `responseMode`, `invitationCompletion` |
| `Google` | OIDC, brand `Google` | `clientId`, `clientSecret` | `authority` (default `https://accounts.google.com`), `scopes`, `responseMode`, `invitationCompletion` |
| `Apple` | OIDC, brand `Apple` | `clientId`, `clientSecret` | `authority` (default `https://appleid.apple.com`), `scopes`, `responseMode` (`FormPost` when `name` or `email` is requested), `invitationCompletion` |
| `OpenId` | OIDC, brand `Custom` | `authority`, `clientId`, `clientSecret` | `scopes`, `responseMode`, `invitationCompletion` |
| `GitHub` | OAuth 2.0, brand `GitHub` | `clientId`, `clientSecret` | `authorizationEndpoint`, `tokenEndpoint`, `userInformationEndpoint`, `verifiedEmailEndpoint`, `issuer` (defaults are github.com), `scopes` (default `read:user user:email`), `invitationCompletion` |

`scopes` is a comma- or space-separated list. The `clientSecret` of `Apple` is the signed client-secret token Apple
requires. For certificate or federated credentials, configure the provider directly instead of through the contract.

A missing required key stops AuthProxy before it listens, with one line and exit code 78:

```text
AuthProxy cannot start: Environment 'production' is missing required key 'authentication.providers.EntraId.clientSecret' for provider 'EntraId' (kind EntraId). Set it as the configuration key ...
```

The message names the key, the provider identity and the environment. It never contains a value.

## Secrets

AuthProxy never reads secrets from command-line arguments and never logs them. A key is resolved from the first of:

1. The configuration key `Cratis:AuthProxy:Application:Environment:<key>`.
2. The key with `_FILE` appended, whose value is the path of a file holding the value
   (`...:authentication.providers.GitHub.clientSecret_FILE=/run/secrets/github`).
3. A file named exactly `<key>` in the secrets directory
   (`/run/secrets/cratis/authentication.providers.GitHub.clientSecret`).

A trailing newline in a file is removed. Mount a Kubernetes Secret as a volume and point `SecretsDirectory` at it
and each entry of the Secret becomes a key. The `cratis` CLI resolves passphrase, Azure Key Vault and HashiCorp Vault
secrets before it starts the container, and Stage Manager mounts them; AuthProxy needs no knowledge of those providers.

## Onboarding

When the application has onboarding, set `Cratis:AuthProxy:Application:Onboarding` to `true` and supply the
settings of the application's own Ante. They map onto [`Cratis:AuthProxy:Invite`](lobby/index.md).

| Key | Maps to | Required |
| --- | --- | --- |
| `onboarding.stageUrl` | `Invite:StageUrl` | yes |
| `onboarding.exchangeUrl` | `Invite:ExchangeUrl` | yes |
| `onboarding.tokenMetadataUrl` | `Invite:TokenMetadataUrl` | yes |
| `onboarding.issuer` | `Invite:Issuer` | yes |
| `onboarding.audience` | `Invite:Audience` | yes |
| `onboarding.lobbyFrontendBaseUrl` | `Invite:Lobby:Frontend:BaseUrl` | yes |
| `onboarding.attestation.issuer` | `Invite:Attestation:Issuer` | yes |
| `onboarding.attestation.audience` | `Invite:Attestation:Audience` | yes |
| `onboarding.attestation.keyId` | `Invite:Attestation:ActiveKeyId` and the key's id | yes |
| `onboarding.attestation.privateKeyPem` | `Invite:Attestation:SigningKeys:0:PrivateKeyPem` (a secret) | yes |
| `onboarding.lobbyBackendBaseUrl` | `Invite:Lobby:Backend:BaseUrl` | no |
| `onboarding.registrationBaseUrl` | `Invite:Lobby:Registration:BaseUrl` | no |
| `onboarding.subjectAlreadyExistsUrl` | `Invite:SubjectAlreadyExistsUrl` | no |
| `onboarding.tenantClaim` | `Invite:TenantClaim` (default `tenant_id`) | no |
| `onboarding.emailClaim` | `Invite:EmailClaim` (default `email`) | no |
| `onboarding.attestation.lifetimeSeconds` | `Invite:Attestation:Lifetime` (10 to 60) | no |

With onboarding on, every provider also gets invitation completion: a canonical identity whose provider key is the
lowercase identity and whose subject is `oid` for `EntraId`, `sub` otherwise (`sub` mapped from the GitHub user id).
Set a provider's `invitationCompletion` to `false` to exclude it. The signing key must be an RSA key of at least 2048
bits; AuthProxy's existing validation checks it. See [Invitation token keys](lobby/invitation-token-keys.md).

## Development

`cratis run` sets `Development` to `true`. Then, and only then, a URL in the contract may use HTTP, and only on a
loopback address (`localhost`, `127.0.0.1`, `[::1]`). Everything else, and everything when `Development` is not
`true`, must be HTTPS, with no user information or fragment in the URL.

Register these callback URLs with each provider for local sign-in (the port is the one AuthProxy listens on):

| Identity | Callback URL |
| --- | --- |
| `EntraId` | `http://localhost:<port>/signin-entraid` |
| `GitHub` | `http://localhost:<port>/signin-github` |
| `Partner` | `http://localhost:<port>/signin-partner` |

Entra ID accepts `http://localhost` redirect URIs; providers that require HTTPS callbacks (Apple) cannot be used
locally without a tunnel.

## Running with the container

```bash
docker run -p 8080:8080 \
  --env-file application-contract.env \
  -v ./secrets:/run/secrets/cratis:ro \
  -e Cratis__AuthProxy__Application__SecretsDirectory=/run/secrets/cratis \
  cratis/authproxy
```
