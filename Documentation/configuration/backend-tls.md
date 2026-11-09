---
title: Backend TLS
description: Configure AuthProxy backend TLS: mount a client certificate and private CA bundle, rotate PEM files live, and require HTTPS on every identity-bearing hop.
---

# Backend TLS

Use backend TLS to protect forwarded identity between AuthProxy and the applications behind it. TLS verifies the backend's certificate and DNS name; a client certificate lets the backend authenticate AuthProxy too. Configure the backend to require and authorize that client identity. Offering a client certificate alone does not make a backend reject other callers.

[Forwarded identity signing](forwarded-identity-signing.md) remains a separate control: it binds identity headers to an audience, method, path, timestamp and nonce. TLS protects the connection, including the query and body that the proof does not cover. Keep backend ingress restrictions in place as well.

## Configure mounted certificates

Mount the files read-only and configure `Cratis:AuthProxy`:

```json
{
  "Cratis": {
    "AuthProxy": {
      "BackendTls": {
        "RequireTlsOnIdentityHops": true,
        "ClientCertificate": {
          "CertificatePath": "/run/authproxy/backend/client.crt",
          "KeyPath": "/run/authproxy/backend/client.key"
        },
        "TrustedCertificateAuthoritiesPath": "/run/authproxy/backend/ca-bundle.crt",
        "ReloadInterval": "00:01:00"
      }
    }
  }
}
```

The client certificate and unencrypted private key must be matching PEM files. The first certificate is the client leaf; it must be currently valid and, when an extended-key-usage restriction is present, permit client authentication. Keep the private key in your secret store, not in committed configuration or the image. Both paths are required when `ClientCertificate` is configured. An invalid, unreadable, expired or mismatched configured pair refuses startup, including in local development.

The trust bundle is optional. An empty path uses system trust. A configured PEM bundle replaces system roots for backend hosts; it does not add a fallback to public roots. Backend certificates still need a valid chain, validity period, server-authentication usage and matching hostname. AuthProxy does not fetch missing intermediates or perform online revocation checks for a custom bundle, so origins must present their intermediate chain. OIDC providers and other non-backend hosts keep system trust and are not offered the backend client certificate.

The policy covers YARP proxy requests, bearer routes, identity-details calls and selectable-tenant-list calls. Sign-in callbacks, client-credential callbacks, on-behalf grant checks and session notifications also use their configured backend hosts. With `BackendTls:RequireTlsOnIdentityHops` enabled, every identity-bearing destination extends this host set: all service backends and frontends, tenant-list endpoints, resolved client-credential verification endpoints, invitation staging/exchange, link exchange, sign-in notifications, capability verification and tenant verification. With the setting disabled, the existing host policy is unchanged, including its signed frontends and back channels.

Host matching is case-insensitive and does not distinguish ports: do not share an identity-bearing hostname with unrelated endpoints if those endpoints must not receive the client identity. Registration URLs and identity providers do not extend this host set. An identity provider sharing an independently configured covered host is subject to that host's backend policy.

Sticky replica routing keeps the configured DNS authority as the TLS target even when connecting to a discovered IP address. Issue server certificates for that DNS name, not for the replica's incidental IP address.

AuthProxy's factory-managed back-channel clients do not store or replay response cookies, including verifier, callback and metadata clients. A backend cannot establish a cookie session that subsequent calls inherit through a pooled handler. Each call carries only its explicitly constructed identity and credentials; documented callback identity headers remain unchanged. OAuth, OIDC and JWT bearer provider back channels also do not store or replay response cookies.

## Identity-hop requirements

Set `Cratis:AuthProxy:BackendTls:RequireTlsOnIdentityHops` to `true` to require **HTTPS on every identity-bearing hop**, even without forwarded-identity signing. This is an operator-controlled server setting, not a caller header or request option. It defaults to `false` in this minor release; a future major release will make it the default. With it off, existing transport behavior is unchanged, including the signing requirements and LocalDevelopment exemptions.

With the setting enabled, startup validation identifies the configuration key and refuses a non-HTTPS identity-bearing target before identity is sent. This covers service backend and frontend URLs (including frontend-only services), tenant-list endpoints, callback backends, resolved client-credential verification endpoints, invitation staging/exchange, link exchange, sign-in notifications, capability verification and tenant verification. Client-credential validation resolves `VerificationPath` exactly as the verifier does, including absolute URLs that differ from the backend. Service backends also carry on-behalf grant checks and session notifications.

Signed service and tenant-list hops additionally require a configured client certificate outside `LocalDevelopment`, as before. Enabling the setting for unsigned hops does not require a client certificate: system-trusted HTTPS is sufficient, or configure a private CA bundle and optional client identity above.

Client-credential and capability verifier destinations, queued callback destinations, resolved tenant-verification URLs, and discovered OIDC token endpoints are checked against the current configuration before a client is created. A refused verifier URL returns its existing failure result; a refused token endpoint returns provider unavailable, without sending a request.

On-behalf calls retain their existing per-call attestations, not the v1 header envelope. Their signed service's backend requires HTTPS outside `LocalDevelopment`, and the configured client certificate applies to its hosts. Body-carrying invitation, link and sign-in notification flows are transport-only in the signing inventory; their body identity is not covered by v1.

For a developer machine only, explicitly select:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Profile": "LocalDevelopment"
    }
  }
}
```

With the TLS setting enabled, `LocalDevelopment` permits HTTP only for loopback targets (`localhost`, `127.0.0.1` or `::1`). With it disabled, the existing back-channel exemption still includes non-loopback targets, even with signing. The profile permits a missing client certificate and emits a startup warning when that exception is used. It never disables certificate or hostname validation on HTTPS, and configured certificate files must still be valid. `ASPNETCORE_ENVIRONMENT=Development` does not select this profile.

Aspire's [`WithSignedForwardingTo`](../aspire/index.md#signed-forwarded-identity) selects AuthProxy's local profile in **run mode only**. Publishing emits no development-profile override: provision signing secrets, HTTPS backend URLs and backend TLS credentials for the deployed service. This does not select Arc's separate local-development identity profile.

## Enable for an existing deployment

Before turning on `BackendTls:RequireTlsOnIdentityHops`:

1. Inventory every destination listed above, including unsigned services, frontends, callbacks and tenant-verification templates. Provision HTTPS listeners and certificates matching their configured DNS names.
2. Change each identity-bearing URL to `https://`. Check absolute `ClientCredentials:VerificationPath` values as well as backend base URLs. Mount a CA bundle if the servers use private roots; configure client credentials where the receiver requires mutual TLS.
3. For Aspire, choose an HTTPS endpoint explicitly, for example `WithBackend("main", api, "https")`, and call `WithRequiredTlsOnIdentityHops()` on AuthProxy. Apply the same endpoint selection to frontends, tenant lists and other identity-bearing resource registrations. The helper only sets server configuration; AuthProxy startup performs validation, and it does not enable signing or select a development profile.
4. Enable the setting in a test deployment and verify every flow before enabling it in production. Do not use `LocalDevelopment` to bypass production requirements. A deployment that leaves the setting off and has no signing keeps its current behavior, but should opt in ahead of the future major default.

## Rotate files without restarting

Replace the mounted client certificate and key together, preferably by atomically replacing a secret volume or symlink. AuthProxy polls their contents, including the CA bundle, every `ReloadInterval` (one minute by default; at least five seconds). A valid changed snapshot becomes visible atomically to new TLS handshakes. Invalid or partial replacements produce a redacted warning and leave the last valid snapshot in use. If that client certificate expires, AuthProxy logs an error on the next poll; receivers must reject it rather than relying on the previous successful handshake.

Existing TLS connections do not renegotiate when files change. When TLS material is configured, pooled connections have a lifetime equal to the reload interval, so a request after that connection lifetime expires opens a new connection and presents the current client certificate. Long-running streams can continue on an existing connection. Allow for both the polling interval and connection turnover during rotation.

For a CA migration, mount an overlap bundle containing both old and new roots, wait for reload, change the backend's server certificate, then remove the old root after connection turnover. AuthProxy never installs roots into the machine's global trust store.

## Verify the hop

Startup reports show the configured transport (`PlainHttp`, `Tls` or `MutualTls`) beside each identity flow and report client subject, SAN, SHA-256 fingerprint, expiration and custom anchor count. No private key or PEM content is logged. Use the receiving backend's TLS observations to confirm it received and authorized the intended client certificate; then verify that signed identity is accepted.

A wrong CA, expired leaf or mismatched hostname refuses the connection. Logs identify the target host and a fixed validation reason without certificate contents. Direct identity-details and tenant-list calls retain their existing indeterminate/unavailable behavior on connection failure; they do not silently retry unsigned or over HTTP.
