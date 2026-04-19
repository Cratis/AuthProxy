// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ErrorPages;
using Cratis.AuthProxy.Identity;
using Cratis.AuthProxy.Invites;
using Cratis.AuthProxy.ReverseProxy;
using Cratis.AuthProxy.Tenancy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
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
        app.UseStaticFiles();
        UsePagesStaticFiles(app);
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

    static void UsePagesStaticFiles(WebApplication app)
    {
        var config = app.Services.GetRequiredService<IOptionsMonitor<C.AuthProxy>>();

        app.UseStaticFiles(new StaticFileOptions
        {
            FileProvider = new PagesFileProvider(app.Environment, config),
            RequestPath = WellKnownPaths.Pages,
        });
    }

    static void MapIngressEndpoints(this WebApplication app)
    {
        // All requests under /_pages are served as static files (anonymous by design).
        // Any path not matched by the static file middleware is returned as 404 without
        // requiring authentication, so the pages are never subject to auth challenges.
        app.Map($"{WellKnownPaths.Pages}/{{**path}}", () => Results.NotFound())
            .AllowAnonymous();

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
        app.MapGet($"{WellKnownPaths.LoginPrefix}/{{scheme}}", async (string scheme, HttpContext context, IOptionsMonitor<C.Authentication> authConfig) =>
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
            var properties = new AuthenticationProperties { RedirectUri = returnUrl };
            await context.ChallengeAsync(scheme, properties);
        })
        .AllowAnonymous();

        app.MapMethods($"{WellKnownPaths.LoginPrefix}/{{scheme}}", [HttpMethods.Head], async (string scheme, HttpContext context, IOptionsMonitor<C.Authentication> authConfig) =>
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
            var properties = new AuthenticationProperties { RedirectUri = returnUrl };
            await context.ChallengeAsync(scheme, properties);
        })
        .AllowAnonymous();

        // Serves the bundled React login-selection SPA.
        var indexHtmlPath = Path.Combine(app.Environment.WebRootPath, "index.html");
        app.MapGet($"{WellKnownPaths.LoginPage}/{{**path}}", async context =>
        {
            context.Response.ContentType = "text/html";
            await context.Response.SendFileAsync(indexHtmlPath);
        })
        .AllowAnonymous();
    }

    sealed class PagesFileProvider(IWebHostEnvironment environment, IOptionsMonitor<C.AuthProxy> config) : IFileProvider
    {
        public IDirectoryContents GetDirectoryContents(string subpath) => NotFoundDirectoryContents.Singleton;

        public IFileInfo GetFileInfo(string subpath)
        {
            var relativePath = subpath.TrimStart('/');
            if (string.IsNullOrWhiteSpace(relativePath))
            {
                return new NotFoundFileInfo(subpath);
            }

            foreach (var directory in GetCandidateDirectories())
            {
                var directoryFullPath = Path.GetFullPath(directory);
                var candidateFullPath = Path.GetFullPath(Path.Combine(directoryFullPath, relativePath));
                var startsWithDirectory = candidateFullPath.StartsWith($"{directoryFullPath}{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(candidateFullPath, directoryFullPath, StringComparison.OrdinalIgnoreCase);

                if (!startsWithDirectory || !File.Exists(candidateFullPath))
                {
                    continue;
                }

                return new PhysicalPathFileInfo(candidateFullPath);
            }

            return new NotFoundFileInfo(subpath);
        }

        public IChangeToken Watch(string filter) => NullChangeToken.Singleton;

        IEnumerable<string> GetCandidateDirectories()
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

        sealed class PhysicalPathFileInfo(string fullPath) : IFileInfo
        {
            readonly FileInfo _fileInfo = new(fullPath);

            public bool Exists => _fileInfo.Exists;

            public long Length => _fileInfo.Length;

            public string PhysicalPath => _fileInfo.FullName;

            public string Name => _fileInfo.Name;

            public DateTimeOffset LastModified => new(_fileInfo.LastWriteTimeUtc, TimeSpan.Zero);

            public bool IsDirectory => false;

            public Stream CreateReadStream() => _fileInfo.OpenRead();
        }
    }
}
