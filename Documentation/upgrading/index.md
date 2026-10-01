---
title: Upgrading
description: Breaking changes between AuthProxy releases, what each one now denies or changes, and how to keep the previous behavior.
---

Notes on releases that change what an unchanged configuration does.

| Change | Summary |
|--------|---------|
| [Tenant and service headers follow Arc](tenant-and-service-headers.md) | The tenant is forwarded as `x-cratis-tenant-id` instead of `Tenant-ID`, services are selected by `x-cratis-microservice`, and a client can no longer send either tenant header. |
