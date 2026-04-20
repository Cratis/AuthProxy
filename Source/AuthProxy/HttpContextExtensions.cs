// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

/// <summary>
/// Provides helper methods for classifying well-known AuthProxy HTTP requests.
/// </summary>
public static class HttpContextExtensions
{
    const string SignInPathPrefix = "/signin-";

    /// <summary>
    /// Gets the current request path and query string as a single relative URL.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns>The current request path and query string.</returns>
    public static string GetPathAndQuery(this HttpContext context) => $"{context.Request.Path}{context.Request.QueryString}";

    /// <summary>
    /// Determines whether the request has a pending invitation cookie.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> if a pending invitation cookie exists; otherwise <see langword="false"/>.</returns>
    public static bool HasPendingInvitation(this HttpContext context) => context.Request.Cookies.ContainsKey(Cookies.InviteToken);

    /// <summary>
    /// Determines whether the request targets an invitation URL.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> if the request is an invitation URL; otherwise <see langword="false"/>.</returns>
    public static bool IsInvitation(this HttpContext context) => context.Request.Path.StartsWithSegments(WellKnownPaths.InvitePathPrefix);

    /// <summary>
    /// Determines whether the request targets one of the login endpoints.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> if the request is a login endpoint; otherwise <see langword="false"/>.</returns>
    public static bool IsLogin(this HttpContext context) =>
        context.Request.Path.StartsWithSegments(WellKnownPaths.LoginPrefix)
        || context.Request.Path.StartsWithSegments(WellKnownPaths.LoginPage);

    /// <summary>
    /// Determines whether the request targets the well-known providers endpoint.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> if the request targets the providers endpoint; otherwise <see langword="false"/>.</returns>
    public static bool IsProviders(this HttpContext context) => context.Request.Path.StartsWithSegments(WellKnownPaths.Providers);

    /// <summary>
    /// Determines whether the request targets the AuthProxy authentication user interface.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> if the request is part of the authentication UI; otherwise <see langword="false"/>.</returns>
    public static bool IsAuthenticationUI(this HttpContext context) => context.IsLogin() || context.IsProviders();

    /// <summary>
    /// Determines whether the request targets any authentication bootstrap endpoint.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <returns><see langword="true"/> if the request is part of authentication bootstrap; otherwise <see langword="false"/>.</returns>
    public static bool IsAuthenticationBootstrap(this HttpContext context) =>
        context.IsAuthenticationUI() || (context.Request.Path.Value?.StartsWith(SignInPathPrefix, StringComparison.OrdinalIgnoreCase) ?? false);

    /// <summary>
    /// Attempts to extract the invitation token from the current invitation request path.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <param name="invitationToken">The extracted invitation token when present.</param>
    /// <returns><see langword="true"/> if an invitation token was extracted; otherwise <see langword="false"/>.</returns>
    public static bool TryGetInvitationToken(this HttpContext context, out string invitationToken)
    {
        invitationToken = string.Empty;

        if (!context.Request.Path.StartsWithSegments(WellKnownPaths.InvitePathPrefix, out var remaining))
        {
            return false;
        }

        invitationToken = remaining.Value?.TrimStart('/') ?? string.Empty;

        return true;
    }

    /// <summary>
    /// Attempts to get the pending invitation token from the request cookies.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> to evaluate.</param>
    /// <param name="invitationToken">The pending invitation token when present.</param>
    /// <returns><see langword="true"/> if a pending invitation token exists; otherwise <see langword="false"/>.</returns>
    public static bool TryGetPendingInvitationToken(this HttpContext context, out string invitationToken)
    {
        invitationToken = string.Empty;

        if (!context.Request.Cookies.TryGetValue(Cookies.InviteToken, out var token)
            || string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        invitationToken = token;

        return true;
    }
}