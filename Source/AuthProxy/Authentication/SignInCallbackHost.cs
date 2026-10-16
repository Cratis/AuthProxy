// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ReverseProxy;
using Microsoft.AspNetCore.WebUtilities;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Sends a sign-in or a sign-out that starts on one host to the one host the identity-provider handshake runs on.
/// </summary>
/// <remarks>
/// The handshake has to start and finish on the same host, because its correlation and nonce cookies are host-only
/// and the provider is told one callback address. Rather than widen those cookies to the whole domain, the browser is
/// bounced to the callback host, where the handshake runs as it always does, and returns to the original address once
/// the session — which is valid on every host under the cookie domain — exists. Nothing here applies unless
/// <see cref="C.SignIn.CallbackHost"/> is configured.
/// </remarks>
public static class SignInCallbackHost
{
    /// <summary>
    /// The query key that marks a request that was already sent to the callback host once.
    /// </summary>
    /// <remarks>
    /// It is what stops an ingress that rewrites the <c language="text">Host</c> header from turning the bounce into a redirect
    /// loop: a request that carries it and still does not look like the callback host is challenged where it is.
    /// </remarks>
    public const string BouncedQueryKey = "bounced";

    /// <summary>
    /// Gets whether a callback host is configured.
    /// </summary>
    /// <param name="config">The auth proxy configuration.</param>
    /// <returns><see langword="true"/> when <see cref="C.SignIn.CallbackHost"/> names a host; otherwise <see langword="false"/>.</returns>
    public static bool IsConfigured(C.AuthProxy config) => !string.IsNullOrWhiteSpace(config.SignIn?.CallbackHost);

    /// <summary>
    /// Builds the address of the callback host, with the scheme of the current request.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="config">The auth proxy configuration.</param>
    /// <param name="pathAndQuery">The rooted path and query to append.</param>
    /// <param name="address">The absolute address on the callback host.</param>
    /// <returns><see langword="true"/> when a usable callback host is configured; otherwise <see langword="false"/>.</returns>
    public static bool TryBuildAddress(HttpContext context, C.AuthProxy config, string pathAndQuery, out string address)
    {
        address = string.Empty;
        if (!TryGet(config, out var host))
        {
            return false;
        }

        address = $"{context.Request.Scheme}://{host.Value}{pathAndQuery}";
        return true;
    }

    /// <summary>
    /// Builds the address to send a sign-in to when it starts on a host other than the callback host.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="config">The auth proxy configuration.</param>
    /// <param name="scheme">The provider scheme to sign in with.</param>
    /// <param name="returnUrl">Where the person is heading, as a path on this host or an absolute URL.</param>
    /// <param name="location">The address to redirect to.</param>
    /// <returns>
    /// <see langword="true"/> when the sign-in has to move to the callback host; <see langword="false"/> when it runs
    /// here — no callback host, already on it, already bounced once, or answering an invitation.
    /// </returns>
    /// <remarks>
    /// A pending invitation keeps the handshake on the host it started on: the invitation's own cookies are host-only
    /// and would not travel. Such a sign-in needs a callback registered for that host.
    /// </remarks>
    public static bool TryBuildLoginBounce(HttpContext context, C.AuthProxy config, string scheme, string? returnUrl, out string location)
    {
        location = string.Empty;
        if (!TryGet(config, out var host)
            || IsCallbackHost(context, host)
            || context.Request.Query.ContainsKey(BouncedQueryKey)
            || context.HasPendingInvitation()
            || context.Request.Cookies.ContainsKey(Cookies.InvitationEntryState))
        {
            return false;
        }

        var query = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["returnUrl"] = AbsoluteOnThisHost(context, SignInReturnUrl.Resolve(context, config, returnUrl)),
            [BouncedQueryKey] = "1"
        };

        location = QueryHelpers.AddQueryString($"{context.Request.Scheme}://{host.Value}{WellKnownPaths.LoginPrefix}/{scheme}", query);
        return true;
    }

    /// <summary>
    /// Builds the address to send a sign-out to when the identity provider has to be told and the request is not on
    /// the callback host.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="config">The auth proxy configuration.</param>
    /// <param name="target">The validated destination after the sign-out, as a path on this host or an absolute URL.</param>
    /// <param name="location">The address to redirect to.</param>
    /// <returns><see langword="true"/> when the sign-out has to move to the callback host; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// The carrier of the destination is a host-only cookie, and the provider sends the browser back to the callback
    /// host, so the carrier has to be written there. The session is read from the shared cookie on either host.
    /// </remarks>
    public static bool TryBuildLogoutBounce(HttpContext context, C.AuthProxy config, string target, out string location)
    {
        location = string.Empty;
        if (!TryGet(config, out var host) || IsCallbackHost(context, host))
        {
            return false;
        }

        var query = new Dictionary<string, string?>(StringComparer.Ordinal) { ["redirect"] = AbsoluteOnThisHost(context, target) };
        location = QueryHelpers.AddQueryString($"{context.Request.Scheme}://{host.Value}{WellKnownPaths.Logout}", query);
        return true;
    }

    static bool TryGet(C.AuthProxy config, out HostString host)
    {
        host = default;
        return IsConfigured(config) && ServiceRoutes.TryParseHost(config.SignIn!.CallbackHost, out host);
    }

    static bool IsCallbackHost(HttpContext context, HostString callbackHost) => ServiceRoutes.Matches(callbackHost, context.Request);

    static string AbsoluteOnThisHost(HttpContext context, string target) =>
        target.StartsWith('/') ? $"{context.Request.Scheme}://{context.Request.Host.Value}{target}" : target;
}
