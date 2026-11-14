---
title: Verify OAuth-grant forwarding
description: Run an isolated local issuer and an independent receiver to verify the OAuth-grant envelopes AuthProxy forwards, end to end.
---
<!-- Copyright (c) Cratis. All rights reserved. -->
<!-- Licensed under the MIT license. See LICENSE file in the project root for full license information. -->

The consumer E2E lane checks that a locally issued, unbound person access token reaches an independent receiver with a valid v2 OAuth-grant envelope. It also checks the existing Arc client-credentials sample. It does not require a deployed Identity server or external credentials.

## Run the lane

From the AuthProxy repository root, with Docker Compose, OpenSSL, and the .NET 10 and 11 SDKs installed:

```bash
bash E2E/run.sh
```

The script builds AuthProxy from the working tree, starts the test services, runs both clients, and stops the compose stack on success or failure. A nonzero exit means at least one check failed. The receiver's Docker-free conformance check is also available separately:

```bash
dotnet run --project E2E/OAuthGrantReceiver/OAuthGrantReceiver.csproj -c Release -- --self-test
```

The receiver uses the independent Arc v2 reference verifier and all 220 published vectors pinned to Arc revision `de9e176d5f669e2036ff3ab5bf85f60dad6a7d9b`. Its local access-token validator verifies the issuer's ES256 signature, issuer, audience, validity and person binding without using AuthProxy helpers. The receiver stores replay nonces atomically in one process; this is not a multi-replica receiver example.

## Understand the test boundary

The local issuer serves metadata, JWKS and introspection over HTTPS. Each run generates a throwaway CA and an issuer certificate with a DNS SAN for `issuer`. The CA is trusted only through a read-only runtime mount and `SSL_CERT_FILE`; hostname and certificate validation remain enabled. The CA never enters an image or the host trust store. Only the issuer gets its TLS private key. Only AuthProxy receives the envelope's P-256 private signing material; the receiver gets the public key alone. The issuer's access-token signing key is generated in memory at startup.

Gateway-to-receiver HTTP is an explicit `LocalDevelopment` exception, not a production transport example. The receiver supplies the reference verifier's authenticated-transport input under that local exception. Production receivers still need authenticated TLS and shared, atomic replay storage. Keep every service in this lane isolated from real users and credentials: the issuer's mint/revoke/outage controls and the receiver's hostile-request shim intentionally have no authentication.

The receiver verifies principal, tenant, credential UUID, issuer, subject, authentication time, ACR, AMR, cache epoch, sender-binding state and the hash of the independently validated forwarded bearer. The unbound person path emits neither a grant-id nor an actor header; tokens with unverified actor claims are refused instead of promoting those claims into trusted evidence. REST and MCP-shaped JSON-RPC `tools/list` and `tools/call` paths must reach the receiver successfully. The MCP surface is a test subset, not a full lifecycle/session implementation. Successful REST and tool-call responses expose only the verified credential/person identifiers and a hash-match flag. This is a test verifier, not product code or an Arc installer; the manual real-Identity follow-up is described in the E2E README.

## Rejections and cleanup

The client checks revoked tokens, an introspection outage, sender-constrained tokens, client-credentials tokens, unwrapped PATs, wrong audiences and issuers, and cookie-plus-bearer ambiguity. It uses a receiver ingress counter to ensure gateway rejections never reach the backend. The two-second positive introspection cache bounds revocation; the check allows one additional second for scheduling and network latency.

A receiver-local shim retains a successfully admitted request only in memory and checks tampered, forged, stripped and replayed envelopes, a swapped bearer, duplicate envelopes and unknown context headers. Tokens and signed request material are never returned by that shim. Caller-supplied identity and context headers are poisoned before a normal proxy request to verify stripping and reconstruction.

Runtime certificates and private material live in a per-run directory under `.ai-work/e2e/` and are removed after the containers stop. If container cleanup fails, the script retains that directory and prints its path: stop the remaining containers before removing those files. Failure artifacts include only `compose.log`, never the runtime directory. Do not print environment files, request headers, bearer tokens or private material when diagnosing failures.

For production configuration, use [Bearer authentication](authentication.md#bearer-routes-access-tokens-from-an-authorization-server) and [Forwarded identity signing](forwarded-identity-signing.md).
