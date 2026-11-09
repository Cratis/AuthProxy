// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

/// <summary>A deployment with real bearer authentication and an anonymous token-passthrough route.</summary>
public class PassthroughAuthenticationHarness : BearerRouteHarness
{
    public const string PassthroughPath = "/api/passthrough";
    public const string AuthenticatedHeader = "X-Spec-Authenticated";
    public const string TenantHeader = "X-Spec-Tenant";
    public const string ValidatedTokenHeader = "X-Spec-Validated-Token";

    /// <inheritdoc/>
    protected override bool UsesHeaderAuthentication => false;

    /// <inheritdoc/>
    protected override void ConfigureHost(IWebHostBuilder builder)
    {
        const string jwt = $"{C.Authentication.SectionKey}:JwtBearer";
        builder.UseSetting($"{jwt}:Authority", Issuer.Issuer)
            .UseSetting($"{jwt}:MetadataAddress", $"{Issuer.Issuer}.well-known/oauth-authorization-server")
            .UseSetting($"{jwt}:RequireHttpsMetadata", "false")
            .UseSetting($"{jwt}:Audience", Audience)
            .UseSetting($"{jwt}:MapInboundClaims", "false")
            .ConfigureTestServices(services => services.AddSingleton<IStartupFilter, ObserveAuthenticationStartupFilter>());
    }

    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        const string proxy = C.AuthProxy.SectionKey;
        settings[$"{proxy}:Services:app:BearerRoutes:0:Issuers:0:Issuer"] = "https://bearer.example.test/";
        settings[$"{proxy}:Services:app:BearerRoutes:1:Issuers:0:Issuer"] = "https://bearer.example.test/";
        settings[$"{proxy}:Services:app:AnonymousPaths:0"] = PassthroughPath;
        settings[$"{proxy}:Services:app:PassCallerAuthorizationPaths:0"] = PassthroughPath;
        settings[$"{proxy}:Services:app:ClientCredentials:RoutePrefix"] = "/api";
        settings[$"{proxy}:Services:app:ClientCredentials:VerificationPath"] = "/verify";
        settings[$"{proxy}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Claim);
        settings[$"{proxy}:TenantResolutions:0:Options:ClaimType"] = "tid";
        settings[$"{proxy}:TenantResolutions:1:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Claim);
        settings[$"{proxy}:TenantResolutions:1:Options:ClaimType"] = ClientCredentialsDefaults.TenantClaimType;
        settings[$"{proxy}:Tenants:{TenantId}:SourceIdentifiers:0"] = TenantId;
    }

    sealed class ObserveAuthenticationStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, proceed) =>
            {
                context.Response.OnStarting(() =>
                {
                    context.Response.Headers[AuthenticatedHeader] = (context.User.Identity?.IsAuthenticated == true).ToString();
                    context.Response.Headers[TenantHeader] = context.Items[TenancyMiddleware.TenantIdItemKey] as string ?? string.Empty;
                    context.Response.Headers[ValidatedTokenHeader] = context.Items.ContainsKey(ClientCredentialsDefaults.ValidatedTokenPayloadItemKey).ToString();
                    return Task.CompletedTask;
                });
                await proceed();
            });
            next(app);
        };
    }
}
