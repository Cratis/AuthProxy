# AuthProxy

## Authentication and multi-tenancy gateway for ASP.NET Core applications

[![Docker](https://img.shields.io/docker/v/cratis/authproxy?label=Docker&logo=docker&sort=semver)](https://hub.docker.com/r/cratis/authproxy)
[![C# Build](https://github.com/Cratis/AuthProxy/actions/workflows/dotnet-build.yml/badge.svg)](https://github.com/Cratis/AuthProxy/actions/workflows/dotnet-build.yml)
[![Publish](https://github.com/Cratis/AuthProxy/actions/workflows/publish.yml/badge.svg)](https://github.com/Cratis/AuthProxy/actions/workflows/publish.yml)

Cratis AuthProxy is a reverse proxy, built on .NET and [YARP](https://microsoft.github.io/reverse-proxy/), that sits in front of your backend and frontend services and owns the cross-cutting edge concerns of a web application: who the user is, which tenant they belong to, whether they are allowed in, and how someone who was invited gets onboarded.

Requests are authenticated, scoped to a tenant, and enriched with identity **before** they reach your services — the resolved tenant and identity travel on trusted headers, so your application code stays focused on the domain instead of re-implementing OpenID Connect handshakes, tenant resolution, and invite flows in every service.

## The problem it solves

Without a gateway, every service re-implements the same boilerplate: an OIDC handshake, tenant resolution from the host or a claim, a call to fetch the user's profile, an invite-acceptance flow. That code is repetitive, drifts between services, and is exactly what you do not want copy-pasted across a fleet. AuthProxy centralizes it at the edge.

## What it handles

- **Authentication** — OpenID Connect (single or multiple providers with a built-in provider-selection page; Microsoft Entra ID, Google, GitHub, Apple, or any custom OIDC provider), OAuth 2.0, JWT Bearer for machine-to-machine calls, and back-channel client credentials exchanged at `/.cratis/token`.
- **Authorization** — require a claim (a role, a group, a GitHub organization or team) before any request is forwarded.
- **Multi-tenancy** — resolve the current tenant per request from the host, a subdomain, a claim, the route, a selection page, or a fixed value, with optional remote tenant verification. Downstream services receive the tenant on a `Tenant-ID` header.
- **Identity enrichment** — calls a `/.cratis/me` endpoint on your service and attaches the enriched identity to forwarded requests as a trusted header.
- **Invites, registration, and lobby** — invite-based onboarding with signed JWT tokens, self-serve registration, signed attestations, and an optional lobby service for users who are not yet assigned to a tenant.
- **Credential linking** — let an already signed-in user prove control of an additional identity-provider login and associate it with their existing account.
- **Hardening and operations** — trusted-proxy policies for `X-Forwarded-*` headers, capability-based admission for deployments that should answer nothing to unknown callers, sign-in notifications, an opt-in private management listener with liveness/readiness endpoints, and overridable built-in HTML pages (provider selection, tenant selection, errors).

There is no code to write: AuthProxy is configured entirely through the `Cratis:AuthProxy` section of `appsettings.json` (or `Cratis__AuthProxy__` environment variables) and runs as a container in front of your services.

## Quickstart

Run the [`cratis/authproxy`](https://hub.docker.com/r/cratis/authproxy) container in front of your services with a configuration like:

```json
{
  "Cratis": {
    "AuthProxy": {
      "Authentication": {
        "OidcProviders": [
          {
            "Name": "Microsoft",
            "Type": "Microsoft",
            "Authority": "https://login.microsoftonline.com/<tenant-id>/v2.0",
            "ClientId": "<client-id>",
            "ClientSecret": "<client-secret>"
          }
        ]
      },
      "TenantResolutions": [{ "Strategy": "Host" }],
      "Services": {
        "main": {
          "Backend": { "BaseUrl": "http://backend:8080/" },
          "Frontend": { "BaseUrl": "http://frontend:3000/" }
        }
      }
    }
  }
}
```

Requests to `/api/**` are forwarded to the backend; everything else goes to the frontend — authenticated, tenant-resolved, and identity-enriched.

### .NET Aspire

The `Cratis.AuthProxy.Aspire` NuGet package wires AuthProxy into a .NET Aspire AppHost with a fluent API instead of hand-written environment variables:

```csharp
var authproxy = builder.AddAuthProxy("authproxy", tag: "latest")
    .WithHttpEndpoint(port: 8080)
    .WithBackend("main", apiResource)
    .WithFrontend("main", webResource)
    .WithOidcProvider(
        "Microsoft",
        OidcProviderType.Microsoft,
        authority: "https://login.microsoftonline.com/<tenant-id>/v2.0",
        clientId: "<client-id>",
        clientSecret: "<client-secret>")
    .WithHostTenantResolution();
```

Read the [full documentation](https://www.cratis.io/authproxy/) for the complete configuration reference — authentication, authorization, tenancy, services, invites and lobby, webhooks, trusted proxies, and more.

## How it fits with Cratis Arc

AuthProxy is a plain ASP.NET Core service and works in front of *any* backend and frontend you point it at. It pairs naturally with [Arc](https://github.com/Cratis/Arc), the Cratis CQRS framework for ASP.NET Core: Arc exposes the `/.cratis/me` identity endpoint AuthProxy enriches from, and Arc applications read the tenant and identity headers AuthProxy forwards. The [Lens](https://github.com/Cratis/Lens) browser extension builds on the same headers to switch tenant and user identity during development.

## The Cratis ecosystem

This project is part of [Cratis](https://www.cratis.io) — free, MIT-licensed tools for building event-sourced and CQRS applications.

- **[Chronicle](https://github.com/Cratis/Chronicle)** — event-sourcing database and runtime. Orleans-based kernel, pluggable storage (MongoDB default; PostgreSQL, SQL Server, SQLite, in-memory), language-agnostic gRPC contracts. [Docs](https://www.cratis.io/chronicle/)
- **Chronicle clients** — first-class [.NET SDK](https://github.com/Cratis/Chronicle), plus [TypeScript](https://github.com/Cratis/Chronicle.TypeScript), [Kotlin/Java](https://github.com/Cratis/Chronicle.Kotlin), and [Elixir](https://github.com/Cratis/Chronicle.Elixir); [Python](https://github.com/Cratis/Chronicle.Python) coming soon (pre-alpha). AI agents connect through the [Chronicle MCP server](https://github.com/Cratis/Chronicle.Mcp).
- **[Arc](https://github.com/Cratis/Arc)** — opinionated CQRS framework for ASP.NET Core with commands, queries, validation, authorization, and TypeScript proxy generation. Works without event sourcing. [Docs](https://www.cratis.io/arc/)
- **[Components](https://github.com/Cratis/Components)** — React components aligned with Arc patterns. [Docs](https://www.cratis.io/components/)
- **[CLI](https://github.com/Cratis/cli) + Workbench** — inspect and diagnose Chronicle from the terminal or the browser. [Docs](https://www.cratis.io/cli/)
- **Model-first layer (experimental)** — [Studio](https://github.com/Cratis/Studio), [Screenplay](https://github.com/Cratis/Screenplay), [Stage](https://github.com/Cratis/Stage), [Scene](https://github.com/Cratis/Scene), [Prologue](https://github.com/Cratis/Prologue)
- **Supporting** — [Fundamentals](https://github.com/Cratis/Fundamentals), [Specifications](https://github.com/Cratis/Specifications), [Synopsis](https://github.com/Cratis/Synopsis), [Lens](https://github.com/Cratis/Lens), [Narrator](https://github.com/Cratis/Narrator), and free [AI tooling](https://github.com/Cratis/AI) (preview); [Ensemble](https://github.com/Cratis/Ensemble) coming soon (pre-release)
- **[Samples](https://github.com/Cratis/Samples)** — runnable event sourcing and CQRS samples for the whole stack

Everything Cratis publishes today is MIT licensed and free to use.

For general guidance on the core values and principles we adhere to, read more [here](https://github.com/Cratis/.github/blob/main/profile/README.md).

## Contributing / Running locally

If you are looking to contribute or want to build and run AuthProxy locally, start with the [documentation](./Documentation/index.mdx).
