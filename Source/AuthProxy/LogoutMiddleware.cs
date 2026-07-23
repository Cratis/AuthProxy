// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

/// <summary>
/// Middleware that handles the well-known logout endpoint (<see cref="WellKnownPaths.Logout"/>).
/// It signs the user out of the authentication cookie, clears every AuthProxy session cookie and
/// redirects to the validated <c>redirect</c> query-string target.
/// </summary>
/// <remarks>
/// The post-logout redirect target is an absolute URL and can therefore not be validated with the
/// relative-URL check used for tenant selection. Instead it is validated against an allow-list of
/// origins that combines the proxy's own public origin (honoring forwarded headers) with the
/// configured service frontends and lobby frontend. A missing or disallowed target falls back to the
/// application root (<c>/</c>) so the endpoint can never be turned into an open redirect.
/// </remarks>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
public class LogoutMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.AuthProxy> config)
{
    const string RedirectQueryKey = "redirect";
    const string ApplicationRoot = "/";

    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Path.StartsWithSegments(WellKnownPaths.Logout))
        {
            await next(context);
            return;
        }

        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        ClearSessionCookies(context);

        context.Response.StatusCode = StatusCodes.Status302Found;
        context.Response.Headers.Location = ResolveRedirectTarget(context, config.CurrentValue);
    }

    static void ClearSessionCookies(HttpContext context)
    {
        context.Response.Cookies.Delete(Cookies.Identity);
        context.Response.Cookies.Delete(Cookies.Tenant);
        context.Response.Cookies.Delete(Cookies.Tenants);
        context.Response.Cookies.Delete(Cookies.InviteToken);
        context.Response.Cookies.Delete(Cookies.Registration);
        context.Response.Cookies.Delete(Cookies.Providers);
    }

    static string ResolveRedirectTarget(HttpContext context, C.AuthProxy authProxyConfig)
    {
        var requested = context.Request.Query[RedirectQueryKey].FirstOrDefault();
        return IsAllowedRedirect(context, authProxyConfig, requested) ? requested! : ApplicationRoot;
    }

    static bool IsAllowedRedirect(HttpContext context, C.AuthProxy authProxyConfig, string? redirect)
    {
        if (string.IsNullOrWhiteSpace(redirect))
        {
            return false;
        }

        // A relative, single-slash URL is always same-site and therefore safe.
        if (Uri.TryCreate(redirect, UriKind.Relative, out _) && redirect.StartsWith('/') && !redirect.StartsWith("//", StringComparison.Ordinal))
        {
            return true;
        }

        if (!Uri.TryCreate(redirect, UriKind.Absolute, out var target)
            || (target.Scheme != Uri.UriSchemeHttp && target.Scheme != Uri.UriSchemeHttps))
        {
            return false;
        }

        var targetOrigin = target.GetLeftPart(UriPartial.Authority);
        return GetAllowedOrigins(context, authProxyConfig)
            .Contains(targetOrigin, StringComparer.OrdinalIgnoreCase);
    }

    static IEnumerable<string> GetAllowedOrigins(HttpContext context, C.AuthProxy authProxyConfig)
    {
        // The proxy's own public origin as seen by the browser (X-Forwarded-Proto is honored upstream).
        if (context.Request.Host.HasValue
            && Uri.TryCreate($"{context.Request.Scheme}://{context.Request.Host.Value}", UriKind.Absolute, out var self))
        {
            yield return self.GetLeftPart(UriPartial.Authority);
        }

        // Reuse the configured service frontends as permitted post-logout destinations.
        foreach (var service in authProxyConfig.Services.Values)
        {
            if (TryGetOrigin(service.Frontend?.BaseUrl, out var origin))
            {
                yield return origin;
            }
        }

        // The lobby frontend is also a permitted destination when configured.
        if (TryGetOrigin(authProxyConfig.Invite?.Lobby?.Frontend?.BaseUrl, out var lobbyOrigin))
        {
            yield return lobbyOrigin;
        }

        // Any explicitly configured post-logout redirect origins (e.g. a separate marketing site).
        foreach (var configured in authProxyConfig.Logout.AllowedRedirectOrigins)
        {
            if (TryGetOrigin(configured, out var configuredOrigin))
            {
                yield return configuredOrigin;
            }
        }
    }

    static bool TryGetOrigin(string? url, out string origin)
    {
        origin = string.Empty;
        if (string.IsNullOrWhiteSpace(url)
            || !Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            return false;
        }

        origin = uri.GetLeftPart(UriPartial.Authority);
        return true;
    }
}
