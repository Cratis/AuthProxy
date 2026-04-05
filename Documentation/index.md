# Ingress

Welcome to the Cratis Ingress documentation.

Ingress is a lightweight ASP.NET Core gateway service that sits in front of your microservices and handles:

- **Authentication** – OpenID Connect (single or multi-provider) and JWT Bearer support.
- **Tenancy** – flexible per-request tenant resolution from host, claim, route, or a fixed value; optional remote tenant verification.
- **Identity enrichment** – calls a `/.cratis/me` endpoint on your microservices to enrich the identity cookie with application-specific details.
- **Invite / Lobby flow** – invite-based onboarding using signed JWT tokens, with an optional lobby microservice for users who have not yet been assigned a tenant.
- **Custom error pages** – user-friendly HTML pages for error conditions (404, 403, tenant not found, invitation expired/invalid), overridable by mounting a custom pages directory.
- **Reverse proxy** – routes requests to one or more backend and frontend microservices using [YARP](https://microsoft.github.io/reverse-proxy/).

## Getting started

Ingress is configured entirely through `appsettings.json` (or environment variables) under the `Ingress` key.
Refer to the [Configuration](configuration/index.md) section for a complete reference.

