// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Invites;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Registrations;

/// <summary>
/// Middleware that implements the AuthProxy registration bootstrap flow.
/// Visiting <c>/register</c> stores a short-lived cookie and either redirects to the generic
/// provider-selection page or immediately challenges the single configured provider.
/// After authentication completes, the middleware redirects the user to the configured
/// lobby registration endpoint.
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="proxyConfig">The auth proxy configuration monitor.</param>
/// <param name="authConfig">The authentication configuration monitor.</param>
/// <param name="tenantResolver">The tenant resolver used to capture tenant metadata in authentication state.</param>
public class RegistrationMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.AuthProxy> proxyConfig,
    IOptionsMonitor<C.Authentication> authConfig,
    ITenantResolver tenantResolver)
{
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.User.Identity?.IsAuthenticated == true && context.HasPendingRegistration())
        {
            context.Response.Cookies.Delete(Cookies.Registration);

            var registrationUrl = proxyConfig.CurrentValue.Invite?.Lobby?.Registration?.BaseUrl;
            if (!string.IsNullOrWhiteSpace(registrationUrl))
            {
                context.Items[InviteMiddleware.LobbyRedirectUrlItemKey] = registrationUrl;
            }

            await next(context);
            return;
        }

        if (!context.IsRegistration())
        {
            await next(context);
            return;
        }

        var registrationUrlConfigured = !string.IsNullOrWhiteSpace(proxyConfig.CurrentValue.Invite?.Lobby?.Registration?.BaseUrl);
        if (!registrationUrlConfigured)
        {
            await next(context);
            return;
        }

        context.Response.Cookies.Append(Cookies.Registration, "pending", new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
            MaxAge = TimeSpan.FromMinutes(15),
        });

        var providers = GetAllProviders(authConfig.CurrentValue).ToList();
        if (providers.Count > 1)
        {
            context.Response.Redirect(WellKnownPaths.LoginPage);
            return;
        }

        if (providers.Count == 1)
        {
            var scheme = OidcProviderScheme.FromName(providers[0].Name);
            var returnUrl = context.GetPathAndQuery();
            var properties = TenantAuthenticationState.CreateChallengeProperties(context, tenantResolver, returnUrl);
            await context.ChallengeAsync(scheme, properties);
            return;
        }

        await next(context);
    }

    static IEnumerable<OidcProviderInfo> GetAllProviders(C.Authentication config) =>
        config.OidcProviders.Select(OidcProviderScheme.ToProviderInfo)
            .Concat(config.OAuthProviders.Select(OidcProviderScheme.ToProviderInfo));
}
