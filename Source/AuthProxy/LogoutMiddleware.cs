// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using AuthState = Cratis.AuthProxy.Authentication.AuthenticationServiceCollectionExtensions;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

/// <summary>
/// Middleware that handles the well-known logout endpoint (<see cref="WellKnownPaths.Logout"/>) and its
/// post-logout callback (<see cref="WellKnownPaths.LogoutCallback"/>). It performs a full-chain logout:
/// when the session was established through an OIDC provider it initiates RP-initiated logout by redirecting
/// the browser to that provider's end-session endpoint with an <c>id_token_hint</c> and a
/// <c>post_logout_redirect_uri</c> pointing back to the callback; the callback then clears every AuthProxy
/// cookie and redirects to the validated final destination. OAuth 2.0 providers (such as GitHub) have no
/// standard OIDC end-session endpoint, so for those — and whenever there is no active OIDC session — it
/// falls back to a local-only logout that clears cookies and redirects directly.
/// </summary>
/// <remarks>
/// The final destination is validated against an allow-list of origins on both legs of the round-trip (see
/// <see cref="PostLogoutRedirectPolicy"/>) so neither the endpoint nor the callback can be turned into an
/// open redirect. The final target is carried across the identity-provider round-trip in a short-lived
/// HTTP-only cookie rather than in the URL, and is re-validated on the callback.
/// </remarks>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="endSessionEndpointResolver">Resolves the OIDC end-session endpoint for the authenticating provider.</param>
/// <param name="logger">The logger.</param>
public class LogoutMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.AuthProxy> config,
    IEndSessionEndpointResolver endSessionEndpointResolver,
    ILogger<LogoutMiddleware> logger)
{
    const string RedirectQueryKey = "redirect";

    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        // The callback path is a segment under the logout path, so it must be matched first.
        if (context.Request.Path.StartsWithSegments(WellKnownPaths.LogoutCallback))
        {
            await CompleteLogout(context, config.CurrentValue);
            return;
        }

        if (!context.Request.Path.StartsWithSegments(WellKnownPaths.Logout))
        {
            await next(context);
            return;
        }

        await InitiateLogout(context, config.CurrentValue, endSessionEndpointResolver, logger);
    }

    static async Task InitiateLogout(
        HttpContext context,
        C.AuthProxy authProxyConfig,
        IEndSessionEndpointResolver endSessionEndpointResolver,
        ILogger logger)
    {
        var target = PostLogoutRedirectPolicy.ResolveTarget(context, authProxyConfig, context.Request.Query[RedirectQueryKey].FirstOrDefault());

        // Read the id_token and the authenticating provider scheme from the authentication cookie before it is
        // cleared, so an RP-initiated logout can be attempted at the identity provider.
        var authenticated = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        var idToken = authenticated?.Properties?.GetTokenValue(OpenIdConnectParameterNames.IdToken);
        var scheme = ResolveAuthenticationScheme(authenticated?.Properties);
        var endSessionEndpoint = await endSessionEndpointResolver.Resolve(scheme, context.RequestAborted);

        // Always clear the local session immediately. Even when the identity provider cannot be reached the
        // user must end up logged out locally.
        await SignOutAndClearCookies(context);

        context.Response.StatusCode = StatusCodes.Status302Found;

        if (!string.IsNullOrWhiteSpace(endSessionEndpoint) && !string.IsNullOrWhiteSpace(idToken))
        {
            // Carry the validated final destination across the round-trip in a short-lived cookie instead of
            // exposing it to the identity provider in the URL. It is re-validated on the callback.
            SetLogoutRedirectCookie(context, target);
            context.Response.Headers.Location = BuildEndSessionRedirect(context, endSessionEndpoint!, idToken!);
            logger.RedirectingToEndSession(scheme!);
            return;
        }

        // OAuth 2.0 provider, no advertised end-session endpoint, or no active OIDC session: fall back to a
        // local-only logout that redirects straight to the validated destination.
        logger.LocalLogoutOnly(scheme ?? "(none)");
        context.Response.Headers.Location = target;
    }

    static async Task CompleteLogout(HttpContext context, C.AuthProxy authProxyConfig)
    {
        // The identity provider has redirected back after ending its own session. Clear every AuthProxy cookie
        // (idempotent with the initiation leg) and redirect to the validated final destination.
        await SignOutAndClearCookies(context);

        var target = PostLogoutRedirectPolicy.ApplicationRoot;
        if (context.Request.Cookies.TryGetValue(Cookies.LogoutRedirect, out var carried))
        {
            target = PostLogoutRedirectPolicy.ResolveTarget(context, authProxyConfig, carried);
        }

        context.Response.Cookies.Delete(Cookies.LogoutRedirect);
        context.Response.StatusCode = StatusCodes.Status302Found;
        context.Response.Headers.Location = target;
    }

    static string BuildEndSessionRedirect(HttpContext context, string endSessionEndpoint, string idToken)
    {
        var callbackUri = $"{context.Request.Scheme}://{context.Request.Host}{WellKnownPaths.LogoutCallback}";
        var parameters = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [OpenIdConnectParameterNames.IdTokenHint] = idToken,
            [OpenIdConnectParameterNames.PostLogoutRedirectUri] = callbackUri,
        };

        return QueryHelpers.AddQueryString(endSessionEndpoint, parameters);
    }

    static string? ResolveAuthenticationScheme(AuthenticationProperties? properties) =>
        properties is not null
        && properties.Items.TryGetValue(AuthState.AuthenticationSchemeStateKey, out var scheme)
            ? scheme
            : null;

    static async Task SignOutAndClearCookies(HttpContext context)
    {
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        context.Response.Cookies.Delete(Cookies.Identity);
        context.Response.Cookies.Delete(Cookies.Tenant);
        context.Response.Cookies.Delete(Cookies.Tenants);
        context.Response.Cookies.Delete(Cookies.InviteToken);
        context.Response.Cookies.Delete(Cookies.Registration);
        context.Response.Cookies.Delete(Cookies.Providers);
    }

    static void SetLogoutRedirectCookie(HttpContext context, string target)
    {
        context.Response.Cookies.Append(Cookies.LogoutRedirect, target, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
            Path = "/",
            MaxAge = TimeSpan.FromMinutes(5),
            IsEssential = true,
        });
    }
}
