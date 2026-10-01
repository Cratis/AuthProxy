---
title: Upgrading
description: Changes between AuthProxy releases, compatibility transitions, and how to keep the previous behavior.
---

Notes on releases that change what an unchanged configuration does.

| Change | Summary |
|--------|---------|
| [Identity verification is required by default](identity-verification-required-by-default.md) | A service that has a backend is now verified by its `/.cratis/me` answer, and anything but an explicit positive denies. |
| [Tenant and service headers follow Arc](tenant-and-service-headers.md) | Both current and legacy tenant and service headers are forwarded during the transition; legacy forwarding is deprecated, and client-supplied tenant headers are stripped. |
