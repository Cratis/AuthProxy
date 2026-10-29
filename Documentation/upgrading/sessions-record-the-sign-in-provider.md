---
title: Sessions record the sign-in provider
description: Sessions record the provider they were signed in with, and accounts from providers without canonical identity are told apart by provider and subject.
---

## The provider a session was signed in with

Sessions now record the provider they were signed in with. An account from a provider without
[canonical identity](../configuration/authentication.md) is identified by that provider and its subject, so the same
subject from two providers is two accounts.

- When more than one sign-in provider is configured, a session signed in before this version through a provider without
  canonical identity ends once, and the user signs in again.
- With one provider, existing sessions continue.
- After signing in again, a user who belongs to several tenants may be asked to select a tenant again.
- The forwarded `x-ms-client-principal` header is unchanged.
