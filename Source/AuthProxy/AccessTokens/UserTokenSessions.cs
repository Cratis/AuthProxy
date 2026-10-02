// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.AccessTokens;

/// <summary>
/// Ties the server-side token session to the AuthProxy session cookie: created when a sign-in redeems its
/// authorization code and issues its cookie, found again on each authenticated request, and removed when the session ends.
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

    const string PendingSessionKey = "Cratis.AuthProxy.PendingTokenSession";

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
    /// Holds the refresh token on the callback request until sign-in succeeds.
    /// </summary>
    /// <param name="context">The token-response context of the OIDC handler.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    internal static Task Capture(TokenResponseReceivedContext context)
    {
        var services = context.HttpContext.RequestServices;
        var config = services.GetRequiredService<IOptionsMonitor<C.AuthProxy>>().CurrentValue;
        if (!IsForwardingConfigured(config) || context.Properties is null)
        {
            return Task.CompletedTask;
        }

        // A link callback authenticates a second identity without signing it in, so it starts no session.
        if (context.Properties.Items.TryGetValue(LinkMiddleware.LinkModePropertyKey, out var linkMode) && linkMode == "true")
        {
            return Task.CompletedTask;
        }

        var refreshToken = context.TokenEndpointResponse.RefreshToken;
        if (string.IsNullOrEmpty(refreshToken))
        {
            services.GetRequiredService<ILoggerFactory>()
                .CreateLogger(typeof(UserTokenSessions))
                .NoRefreshTokenIssued(context.Scheme.Name);
            return Task.CompletedTask;
        }

        context.HttpContext.Items[PendingSessionKey] = new UserTokenSession(context.Scheme.Name, refreshToken);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Persists the pending token session only when a validated sign-in issues its cookie, replacing any old session.
    /// </summary>
    /// <param name="context">The cookie sign-in context.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    internal static async Task Complete(CookieSigningInContext context)
    {
        var previousSession = Of(context.HttpContext);
        if (previousSession is null
            && context.Options.Cookie.Name is { } cookieName
            && context.HttpContext.Request.Cookies.ContainsKey(cookieName))
        {
            var previousTicket = await context.HttpContext.AuthenticateAsync(context.Scheme.Name);
            previousTicket.Properties?.Items.TryGetValue(PropertiesKey, out previousSession);
        }

        if (previousSession is not null)
        {
            await context.HttpContext.RequestServices.GetRequiredService<IUserTokenStore>().Remove(previousSession, CancellationToken.None);
            context.HttpContext.Items.Remove(HttpContextItemKey);
        }

        context.Properties.Items.Remove(PropertiesKey);
        if (context.HttpContext.Items.Remove(PendingSessionKey, out var pending) && pending is UserTokenSession session)
        {
            var store = context.HttpContext.RequestServices.GetRequiredService<IUserTokenStore>();
            context.Properties.Items[PropertiesKey] = await store.Create(session, CancellationToken.None);
        }
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
    /// Keeps sliding token retention aligned with a successfully validated cookie, even on non-forwarding routes.
    /// </summary>
    /// <param name="context">The cookie validation context.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    internal static async Task RenewRetention(CookieValidatePrincipalContext context)
    {
        if (context.Principal is not null && context.Options.SlidingExpiration && Of(context.HttpContext) is { } sessionId)
        {
            await context.HttpContext.RequestServices.GetRequiredService<IUserTokenStore>().Get(sessionId, context.HttpContext.RequestAborted);
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
