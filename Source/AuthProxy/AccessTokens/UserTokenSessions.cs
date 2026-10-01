// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.AccessTokens;

/// <summary>
/// Ties the server-side token session to the AuthProxy session cookie: created when a sign-in redeems its
/// authorization code, found again on each authenticated request, and removed when the session ends.
/// </summary>
/// <remarks>
/// The session cookie carries only an unguessable identifier, inside its encrypted ticket. The refresh token stays
/// in the <see cref="IUserTokenStore"/>, and the cookie carries no tokens at all.
/// </remarks>
public static class UserTokenSessions
{
    /// <summary>
    /// The authentication-properties item that carries the token session identifier in the session cookie.
    /// </summary>
    public const string PropertiesKey = "Cratis.AuthProxy.TokenSession";

    /// <summary>
    /// The <see cref="HttpContext.Items"/> key holding the token session identifier of the current request's session.
    /// </summary>
    internal const string HttpContextItemKey = "Cratis.AuthProxy.TokenSession";

    /// <summary>
    /// Gets whether any service forwards user access tokens, which is the only case in which refresh tokens are kept.
    /// </summary>
    /// <param name="config">The configuration.</param>
    /// <returns><see langword="true"/> when at least one service declares an access token.</returns>
    public static bool IsForwardingConfigured(C.AuthProxy config) => config.Services.Values.Any(_ => _.AccessToken is not null);

    /// <summary>
    /// Gets the token session identifier of the current request's session, when it has one.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns>The identifier, or <see langword="null"/>.</returns>
    public static string? Of(HttpContext context) => context.Items[HttpContextItemKey] as string;

    /// <summary>
    /// Keeps the refresh token of a completed code redemption server-side and records its identifier on the session.
    /// </summary>
    /// <param name="context">The token-response context of the OIDC handler.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    internal static async Task Capture(TokenResponseReceivedContext context)
    {
        var services = context.HttpContext.RequestServices;
        var config = services.GetRequiredService<IOptionsMonitor<C.AuthProxy>>().CurrentValue;
        if (!IsForwardingConfigured(config) || context.Properties is null)
        {
            return;
        }

        // A link callback authenticates a second identity without signing it in, so it starts no session.
        if (context.Properties.Items.TryGetValue(LinkMiddleware.LinkModePropertyKey, out var linkMode) && linkMode == "true")
        {
            return;
        }

        var refreshToken = context.TokenEndpointResponse.RefreshToken;
        if (string.IsNullOrEmpty(refreshToken))
        {
            services.GetRequiredService<ILoggerFactory>()
                .CreateLogger(typeof(UserTokenSessions))
                .NoRefreshTokenIssued(context.Scheme.Name);
            return;
        }

        var store = services.GetRequiredService<IUserTokenStore>();
        context.Properties.Items[PropertiesKey] = await store.Create(new(context.Scheme.Name, refreshToken), context.HttpContext.RequestAborted);
    }

    /// <summary>
    /// Makes the token session of an authenticated session cookie available to the rest of the request.
    /// </summary>
    /// <param name="context">The cookie validation context.</param>
    internal static void Remember(CookieValidatePrincipalContext context)
    {
        if (context.Properties.Items.TryGetValue(PropertiesKey, out var sessionId) && !string.IsNullOrEmpty(sessionId))
        {
            context.HttpContext.Items[HttpContextItemKey] = sessionId;
        }
    }

    /// <summary>
    /// Removes the token session of a session that is being signed out.
    /// </summary>
    /// <param name="context">The cookie sign-out context.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    internal static async Task Forget(CookieSigningOutContext context)
    {
        if (Of(context.HttpContext) is not { } sessionId)
        {
            return;
        }

        await context.HttpContext.RequestServices.GetRequiredService<IUserTokenStore>().Remove(sessionId, CancellationToken.None);
        context.HttpContext.Items.Remove(HttpContextItemKey);
    }
}
