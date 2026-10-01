---
title: Upgrading
description: Breaking changes between AuthProxy releases, what each one now denies or changes, and how to keep the previous behavior.
---

Notes on releases that change what an unchanged configuration does.

| Change | Summary |
|--------|---------|
| [Identity verification is required by default](identity-verification-required-by-default.md) | A service that has a backend is now verified by its `/.cratis/me` answer, and anything but an explicit positive denies. |
