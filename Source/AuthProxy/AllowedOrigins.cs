// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.ReverseProxy;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

/// <summary>
/// The one allow-list of absolute origins a sign-in or a sign-out may send a browser to, so the login and the
/// logout endpoints can never disagree about which origins are trusted.
/// </summary>
/// <remarks>
/// It combines the proxy's own public origin, the configured service frontends, the lobby frontend and the origins
/// named in <see cref="C.Logout.AllowedRedirectOrigins"/>. A deployment that sets
/// <see cref="C.SignIn.CallbackHost"/> additionally allows the origin of every host a service declares, because
/// that is the deployment that moves a person between those hosts; without it the list is exactly what it always was.
/// <para>
/// Only the <em>scheme</em> half of the proxy's own origin is bounded by the trusted-proxy boundary. The host half is
/// <c language="text">Request.Host</c> as it arrived, so <c language="text">AllowedHosts</c> is what keeps that origin meaning the
/// deployment's own name. See <see cref="PostLogoutRedirectPolicy"/>.
/// </para>
/// <para>
/// Origins are compared as scheme, ASCII (punycode) host and port, so a Unicode host and its punycode spelling are
/// the same origin and a look-alike host is not.
/// </para>
/// </remarks>
public static class AllowedOrigins
{
    /// <summary>
    /// Determines whether an absolute URL is on an allowed origin.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="authProxyConfig">The auth proxy configuration.</param>
    /// <param name="target">The absolute URL to test.</param>
    /// <returns><see langword="true"/> when the origin of <paramref name="target"/> is allowed; otherwise <see langword="false"/>.</returns>
    public static bool Contains(HttpContext context, C.AuthProxy authProxyConfig, Uri target) =>
        target.IsAbsoluteUri
        && string.IsNullOrEmpty(target.UserInfo)
        && Enumerate(context, authProxyConfig).Contains(Key(target), StringComparer.Ordinal);

    /// <summary>
    /// Determines whether an absolute URL is on an allowed origin whose host the session cookie is also valid on.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="authProxyConfig">The auth proxy configuration.</param>
    /// <param name="target">The absolute URL to test.</param>
    /// <returns>
    /// <see langword="true"/> when the origin is allowed and lies inside <see cref="C.Session.CookieDomain"/>; otherwise
    /// <see langword="false"/>. Always <see langword="false"/> when no cookie domain is configured.
    /// </returns>
    /// <remarks>
    /// A person returned to a host the session cookie does not reach would arrive signed out, and a sign-in that can
    /// land anywhere else is an open redirect with extra steps. The check is on the host alone, never on the scheme or
    /// the port, because a cookie domain is a host scope.
    /// </remarks>
    public static bool ContainsWithinCookieDomain(HttpContext context, C.AuthProxy authProxyConfig, Uri target) =>
        Contains(context, authProxyConfig, target)
        && IsWithinCookieDomain(authProxyConfig, target.IdnHost);

    /// <summary>
    /// Determines whether a host lies inside the configured session cookie domain.
    /// </summary>
    /// <param name="authProxyConfig">The auth proxy configuration.</param>
    /// <param name="host">The host, in its ASCII form and without a port.</param>
    /// <returns><see langword="true"/> when a cookie domain is configured and covers the host; otherwise <see langword="false"/>.</returns>
    public static bool IsWithinCookieDomain(C.AuthProxy authProxyConfig, string host) =>
        SessionCookie.DomainOf(authProxyConfig.Session) is { } domain
        && CookieDomainScope.Evaluate(domain, out var normalized) == CookieDomainRejection.None
        && CookieDomainScope.Covers(Ascii(normalized), host.ToLowerInvariant());

    static IEnumerable<string> Enumerate(HttpContext context, C.AuthProxy authProxyConfig)
    {
        // The proxy's own public origin as seen by the browser. The scheme is whatever the forwarded-headers
        // middleware settled on, so it reflects X-Forwarded-Proto only as far as the configured trusted-proxy
        // boundary allows — an untrusted caller cannot add a second origin to this list by naming a scheme.
        // The host is not bounded by that boundary at all; it is Request.Host as it arrived, which the
        // AllowedHosts setting is what constrains. See the remarks on this type.
        if (context.Request.Host.HasValue
            && Uri.TryCreate($"{context.Request.Scheme}://{context.Request.Host.Value}", UriKind.Absolute, out var self))
        {
            yield return Key(self);
        }

        // Reuse the configured service frontends as permitted destinations.
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

        // Any explicitly configured origins (e.g. a separate marketing site).
        foreach (var configured in authProxyConfig.Logout.AllowedRedirectOrigins)
        {
            if (TryGetOrigin(configured, out var configuredOrigin))
            {
                yield return configuredOrigin;
            }
        }

        // The hosts one proxy serves are where a person is moved between once a callback host is configured, and
        // only then. The origin is built with the scheme the request arrived on, so a request that came in over
        // HTTPS never allows the same host over HTTP, and a host declared without a port is the default port only.
        if (!SignInCallbackHost.IsConfigured(authProxyConfig))
        {
            yield break;
        }

        foreach (var host in authProxyConfig.Services.Values.SelectMany(ServiceRoutes.HostsOf))
        {
            if (Uri.TryCreate($"{context.Request.Scheme}://{host.Value}", UriKind.Absolute, out var served))
            {
                yield return Key(served);
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

        origin = Key(uri);
        return true;
    }

    static string Key(Uri uri) => $"{uri.Scheme}://{uri.IdnHost.ToLowerInvariant()}:{uri.Port}";

    static string Ascii(string host) => new System.Globalization.IdnMapping().GetAscii(host).ToLowerInvariant();
}
