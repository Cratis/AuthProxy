---
title: Upgrading
description: Changes between AuthProxy releases, compatibility transitions, and how to keep the previous behavior.
---

Notes on releases that change what an unchanged configuration does.

| Change | Summary |
|--------|---------|
| [Identity verification is required by default](identity-verification-required-by-default.md) | A service that has a backend is now verified by its `/.cratis/me` answer, and anything but an explicit positive denies. |
| [Tenant and service headers follow Arc](tenant-and-service-headers.md) | Both current and legacy tenant and service headers are forwarded during the transition; legacy forwarding is deprecated, and client-supplied tenant headers are stripped. |
| [Selected tenant and upstream headers](selected-tenant-and-upstream-headers.md) | A selected tenant is confirmed for the signed-in account, services stop receiving AuthProxy's own cookies, and the caller's `Authorization` header is removed on session requests unless `CallerAuthorizationHeader` is `Forward`. |
| [Sessions record the sign-in provider](sessions-record-the-sign-in-provider.md) | Accounts from providers without canonical identity are told apart by provider and subject; with several providers configured, older sessions from such providers end once. |
