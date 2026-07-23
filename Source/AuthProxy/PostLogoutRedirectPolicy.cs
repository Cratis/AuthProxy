// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

/// <summary>
/// Validates post-logout redirect targets against an allow-list so the logout endpoint and its callback can
/// never be turned into an open redirect.
/// </summary>
/// <remarks>
/// The post-logout redirect target is an absolute URL and can therefore not be validated with the
/// relative-URL check used for tenant selection. Instead it is validated against an allow-list of origins
/// that combines the proxy's own public origin (honoring forwarded headers) with the configured service
/// frontends, the lobby frontend, and any explicitly configured origins. A missing or disallowed target
/// falls back to the application root (<c>/</c>).
/// </remarks>
public static class PostLogoutRedirectPolicy
{
    /// <summary>
    /// The application root, used as the safe fallback destination when no valid target is supplied.
    /// </summary>
    public const string ApplicationRoot = "/";

    /// <summary>
    /// Resolves the effective redirect target, returning the requested value when it is allowed and the
    /// application root otherwise.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="authProxyConfig">The auth proxy configuration.</param>
    /// <param name="requested">The requested redirect target.</param>
    /// <returns>The validated redirect target, or <see cref="ApplicationRoot"/> when the request is missing or disallowed.</returns>
    public static string ResolveTarget(HttpContext context, C.AuthProxy authProxyConfig, string? requested) =>
        IsAllowed(context, authProxyConfig, requested) ? requested! : ApplicationRoot;

    /// <summary>
    /// Determines whether the supplied redirect target is allowed.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="authProxyConfig">The auth proxy configuration.</param>
    /// <param name="redirect">The redirect target to validate.</param>
    /// <returns><see langword="true"/> when the target is a safe same-site relative path or an allow-listed absolute origin; otherwise <see langword="false"/>.</returns>
    public static bool IsAllowed(HttpContext context, C.AuthProxy authProxyConfig, string? redirect)
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
