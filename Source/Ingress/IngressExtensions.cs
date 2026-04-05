// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Ingress.Configuration;
using Cratis.Ingress.Invites;
using Cratis.Ingress.ReverseProxy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;

namespace Cratis.Ingress;

/// <summary>
/// Extension methods for registering ingress services and configuring the application pipeline
/// on <see cref="WebApplicationBuilder"/> and <see cref="WebApplication"/>.
/// </summary>
public static class IngressExtensions
{
    /// <summary>
    /// Registers all <see cref="IOptions{T}"/> bindings for the ingress configuration sections
    /// and configures forwarded-headers handling.
    /// </summary>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> for chaining.</returns>
    public static WebApplicationBuilder AddIngressConfiguration(this WebApplicationBuilder builder)
    {
        builder.Services
            .AddOptions<IngressConfig>()
            .BindConfiguration("Ingress")
            .ValidateDataAnnotations()
            .ValidateOnStart();

        builder.Services
            .AddOptions<AuthenticationConfig>()
            .BindConfiguration("Authentication")
            .ValidateDataAnnotations()
            .ValidateOnStart();

        builder.Services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            options.KnownIPNetworks.Clear();
            options.KnownProxies.Clear();
        });

        return builder;
    }

    /// <summary>
    /// Configures the middleware pipeline: forwarded headers, static files, authentication,
    /// authorization, tenancy, invites, and the reverse proxy.
    /// Also maps the <c>/.cratis/providers</c> endpoint and the per-provider login endpoints.
    /// </summary>
    /// <param name="app">The <see cref="WebApplication"/> to configure.</param>
    /// <returns>The same <see cref="WebApplication"/> for chaining.</returns>
    public static WebApplication UseIngress(this WebApplication app)
    {
        app.UseForwardedHeaders();
        app.UseStaticFiles();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseMiddleware<TenancyMiddleware>();
        app.UseMiddleware<InviteMiddleware>();

        app.MapIngressEndpoints();
        app.UseReverseProxy();

        return app;
    }

    static void MapIngressEndpoints(this WebApplication app)
    {
        // Returns a JSON array of all configured providers (OIDC + OAuth) used by the login page.
        app.MapGet(WellKnownPaths.Providers, (IOptionsMonitor<AuthenticationConfig> config) =>
        {
            var current = config.CurrentValue;

            var oidcProviders = current.OidcProviders.Select(OidcProviderScheme.ToProviderInfo);
            var oauthProviders = current.OAuthProviders.Select(OidcProviderScheme.ToProviderInfo);

            return Results.Json(oidcProviders.Concat(oauthProviders));
        });

        // Initiates the challenge for the requested provider scheme.
        app.MapGet($"{WellKnownPaths.LoginPrefix}/{{scheme}}", async (string scheme, HttpContext context) =>
        {
            var returnUrl = context.Request.Query["returnUrl"].FirstOrDefault() ?? "/";
            var properties = new AuthenticationProperties { RedirectUri = returnUrl };
            await context.ChallengeAsync(scheme, properties);
        });

        // Serves the bundled React login-selection SPA.
        var indexHtmlPath = Path.Combine(app.Environment.WebRootPath, "index.html");
        app.MapGet($"{WellKnownPaths.LoginPage}/{{**path}}", async context =>
        {
            context.Response.ContentType = "text/html";
            await context.Response.SendFileAsync(indexHtmlPath);
        });
    }
}
