// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ErrorPages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Middleware that intercepts unauthenticated requests and either serves a provider-selection
/// page (when multiple identity providers are configured) or initiates a direct OIDC challenge
/// (when exactly one provider is configured).
/// When the proxy is in lobby mode (<see cref="C.Invite.RedirectToLobbyWhenTenantUnresolved"/> is
/// enabled and a lobby URL is configured), unauthenticated requests without an invite token or
/// pending invite cookie are immediately answered with the <c>invitation-required.html</c> page
/// instead of being redirected to a login provider.
/// Skips invite paths, authentication paths, paths a service declares in
/// <see cref="C.Service.AnonymousPaths"/>, and requests with a pending invite cookie.
/// Both answers are only served to a browser navigating to a document; every other caller is refused
/// with <c>401</c>, because a page or a login redirect reads as a delivered success to a client that
/// checks the status code.
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="proxyConfig">The auth proxy configuration monitor.</param>
/// <param name="authConfig">The authentication configuration monitor.</param>
/// <param name="errorPageProvider">The error page provider used to serve the selection page.</param>
/// <param name="tenantResolver">The tenant resolver used to capture tenant metadata in authentication state.</param>
public class SelectProviderMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.AuthProxy> proxyConfig,
    IOptionsMonitor<C.Authentication> authConfig,
    IErrorPageProvider errorPageProvider,
    ITenantResolver tenantResolver)
{
    static readonly JsonSerializerOptions _serializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.User.Identity?.IsAuthenticated == true
            || context.IsInvitation()
            || context.IsRegistration()
            || context.IsAuthenticationUI()
            || context.IsAnonymousPath(proxyConfig.CurrentValue)
            || context.HasPendingInvitation())
        {
            await next(context);
            return;
        }

        var inviteConfig = proxyConfig.CurrentValue.Invite;
        if (inviteConfig?.RedirectToLobbyWhenTenantUnresolved == true
            && !string.IsNullOrWhiteSpace(inviteConfig.Lobby?.Frontend?.BaseUrl))
        {
            await errorPageProvider.WriteErrorPageAsync(
                context,
                WellKnownPageNames.InvitationRequired,
                StatusCodes.Status401Unauthorized);
            return;
        }

        var config = authConfig.CurrentValue;
        var providers = config.OidcProviders.Select(OidcProviderScheme.ToProviderInfo)
            .Concat(config.OAuthProviders.Select(OidcProviderScheme.ToProviderInfo))
            .ToList();

        // With nothing configured to authenticate against there is nothing to refuse, so the request is
        // forwarded exactly as before. Refusing here would turn a proxy that challenges nobody into one
        // that refuses everybody.
        if (providers.Count == 0)
        {
            await next(context);
            return;
        }

        // Everything below answers a caller that cannot proceed: a selection page, or a redirect to an
        // identity provider's login page. Both are answers to a person in a browser, and both read as a
        // success to everything else — the page arrives as 200, and a client following the redirect ends
        // up reading the provider's login page as 200 too. A caller that is not navigating gets the
        // refusal as a status it can act on instead.
        if (!context.IsDocumentNavigation())
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        if (providers.Count > 1)
        {
            var providersJson = JsonSerializer.Serialize(providers, _serializerOptions);
            context.Response.Cookies.Append(Cookies.Providers, providersJson, new CookieOptions
            {
                HttpOnly = false,
                SameSite = SameSiteMode.Lax,
                Secure = context.Request.IsHttps,
                MaxAge = TimeSpan.FromMinutes(15),
            });

            await errorPageProvider.WriteErrorPageAsync(
                context,
                WellKnownPageNames.SelectProvider,
                StatusCodes.Status200OK);
            return;
        }

        var scheme = OidcProviderScheme.FromName(providers[0].Name);
        var returnUrl = context.GetPathAndQuery();
        var properties = TenantAuthenticationState.CreateChallengeProperties(context, tenantResolver, returnUrl);
        await context.ChallengeAsync(scheme, properties);
    }
}
