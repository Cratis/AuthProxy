// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.ErrorPages;
using Cratis.AuthProxy.Identity;
using Cratis.AuthProxy.Invites;
using Cratis.AuthProxy.ReverseProxy;
using Cratis.AuthProxy.Tenancy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

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
            .AddOptions<C.AuthProxy>()
            .BindConfiguration(C.AuthProxy.SectionKey)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        builder.Services
            .AddOptions<C.Authentication>()
            .BindConfiguration(C.Authentication.SectionKey)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        builder.Services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            options.KnownIPNetworks.Clear();
            options.KnownProxies.Clear();
        });

        builder.Services.AddHttpClient();
        builder.Services.AddSingleton<ITenantVerifier, TenantVerifier>();
        builder.Services.AddSingleton<IErrorPageProvider, ErrorPageProvider>();

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
        app.Map(WellKnownPaths.Pages, pagesApp => ConfigurePagesPipeline(pagesApp, app.Environment, app.Services.GetRequiredService<IOptionsMonitor<C.AuthProxy>>()));
        app.UseStaticFiles();
        app.UseAuthentication();
        app.UseMiddleware<Authentication.SelectProviderMiddleware>();
        app.UseAuthorization();
        app.UseMiddleware<TenancyMiddleware>();
        app.UseMiddleware<InviteMiddleware>();
        app.UseMiddleware<IdentityMiddleware>();
        app.UseMiddleware<InviteRedirectMiddleware>();

        app.MapIngressEndpoints();
        app.UseReverseProxy();

        return app;
    }

    static void MapIngressEndpoints(this WebApplication app)
    {
        // Returns a JSON array of all configured providers (OIDC + OAuth) used by the login page.
        app.MapGet(WellKnownPaths.Providers, (IOptionsMonitor<C.AuthProxy> config) =>
        {
            var current = config.CurrentValue.Authentication;

            var oidcProviders = current.OidcProviders.Select(OidcProviderScheme.ToProviderInfo);
            var oauthProviders = current.OAuthProviders.Select(OidcProviderScheme.ToProviderInfo);

            return Results.Json(oidcProviders.Concat(oauthProviders));
        })
        .AllowAnonymous();

        app.MapMethods(WellKnownPaths.Providers, [HttpMethods.Head], () => Results.Ok())
            .AllowAnonymous();

        // Initiates the challenge for the requested provider scheme.
        app.MapGet($"{WellKnownPaths.LoginPrefix}/{{scheme}}", async (string scheme, HttpContext context, IOptionsMonitor<C.Authentication> authConfig, ITenantResolver tenantResolver) =>
        {
            var config = authConfig.CurrentValue;
            var providerExists = config.OidcProviders.Any(p => OidcProviderScheme.FromName(p.Name) == scheme)
                || config.OAuthProviders.Any(p => OidcProviderScheme.FromName(p.Name) == scheme);

            if (!providerExists)
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                await context.Response.WriteAsync($"Provider '{scheme}' is not configured.");
                return;
            }

            var returnUrl = context.Request.Query["returnUrl"].FirstOrDefault() ?? "/";
            var properties = TenantAuthenticationState.CreateChallengeProperties(context, tenantResolver, returnUrl);
            await context.ChallengeAsync(scheme, properties);
        })
        .AllowAnonymous();

        app.MapMethods($"{WellKnownPaths.LoginPrefix}/{{scheme}}", [HttpMethods.Head], async (string scheme, HttpContext context, IOptionsMonitor<C.Authentication> authConfig, ITenantResolver tenantResolver) =>
        {
            var config = authConfig.CurrentValue;
            var providerExists = config.OidcProviders.Any(p => OidcProviderScheme.FromName(p.Name) == scheme)
                || config.OAuthProviders.Any(p => OidcProviderScheme.FromName(p.Name) == scheme);

            if (!providerExists)
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }

            var returnUrl = context.Request.Query["returnUrl"].FirstOrDefault() ?? "/";
            var properties = TenantAuthenticationState.CreateChallengeProperties(context, tenantResolver, returnUrl);
            await context.ChallengeAsync(scheme, properties);
        })
        .AllowAnonymous();

        // Serves the bundled React login-selection SPA.
        var webRootPath = app.Environment.WebRootPath ?? Path.Combine(app.Environment.ContentRootPath, "wwwroot");
        var indexHtmlPath = Path.Combine(webRootPath, "index.html");
        app.MapGet($"{WellKnownPaths.LoginPage}/{{**path}}", async context =>
        {
            context.Response.ContentType = "text/html";
            await context.Response.SendFileAsync(indexHtmlPath);
        })
        .AllowAnonymous();
    }

    static void ConfigurePagesPipeline(IApplicationBuilder app, IWebHostEnvironment environment, IOptionsMonitor<C.AuthProxy> config)
    {
        var pagesContentTypeProvider = new FileExtensionContentTypeProvider();

        app.Run(async context =>
        {
            if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method))
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }

            var relativePath = context.Request.Path.Value?.TrimStart('/');
            if (string.IsNullOrWhiteSpace(relativePath))
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }

            var assetPath = ResolvePageAssetPath(environment, config, relativePath);
            if (assetPath is null)
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }

            if (!pagesContentTypeProvider.TryGetContentType(assetPath, out var contentType))
            {
                contentType = "application/octet-stream";
            }

            context.Response.ContentType = contentType;

            if (HttpMethods.IsHead(context.Request.Method))
            {
                var fileInfo = new FileInfo(assetPath);
                context.Response.ContentLength = fileInfo.Length;
                return;
            }

            await context.Response.SendFileAsync(assetPath);
        });
    }

    static string? ResolvePageAssetPath(IWebHostEnvironment environment, IOptionsMonitor<C.AuthProxy> config, string relativePath)
    {
        foreach (var directory in GetCandidateDirectories(environment, config))
        {
            var directoryFullPath = Path.GetFullPath(directory);
            var candidateFullPath = Path.GetFullPath(Path.Combine(directoryFullPath, relativePath));
            var isWithinDirectory = candidateFullPath.StartsWith($"{directoryFullPath}{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase)
                || string.Equals(candidateFullPath, directoryFullPath, StringComparison.OrdinalIgnoreCase);

            if (isWithinDirectory && File.Exists(candidateFullPath))
            {
                return candidateFullPath;
            }
        }

        return null;
    }

    static IEnumerable<string> GetCandidateDirectories(IWebHostEnvironment environment, IOptionsMonitor<C.AuthProxy> config)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var configuredPath = config.CurrentValue.PagesPath;
        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            var resolvedConfiguredPath = Path.IsPathRooted(configuredPath)
                ? configuredPath
                : Path.Combine(environment.ContentRootPath, configuredPath);

            if (Directory.Exists(resolvedConfiguredPath) && seen.Add(resolvedConfiguredPath))
            {
                yield return resolvedConfiguredPath;
            }
        }

        var defaultPagesPath = Path.Combine(environment.ContentRootPath, "Pages");
        if (Directory.Exists(defaultPagesPath) && seen.Add(defaultPagesPath))
        {
            yield return defaultPagesPath;
        }
    }
}
