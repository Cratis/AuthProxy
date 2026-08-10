// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ErrorPages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
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
/// Skips invite paths, registration paths, a provider's login-challenge endpoint, the providers and
/// token endpoints, paths a service declares in <see cref="C.Service.AnonymousPaths"/>, and requests
/// with a pending invite cookie. It does NOT skip its own selection-page path — a request landing there
/// directly (e.g. a redirect from the cookie authentication handler, or an invite flow) is exactly what
/// this middleware answers.
/// Both answers are only served to a browser navigating to a document; every other caller is refused
/// with <c>401</c>, because a page or a login redirect reads as a delivered success to a client that
/// checks the status code.
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="proxyConfig">The auth proxy configuration monitor.</param>
/// <param name="authConfig">The authentication configuration monitor.</param>
/// <param name="errorPageProvider">The error page provider used to serve the selection page.</param>
/// <param name="tenantResolver">The tenant resolver used to capture tenant metadata in authentication state.</param>
/// <param name="schemeProvider">The authentication scheme provider, used to name a challenge on a refusal.</param>
public class SelectProviderMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.AuthProxy> proxyConfig,
    IOptionsMonitor<C.Authentication> authConfig,
    IErrorPageProvider errorPageProvider,
    ITenantResolver tenantResolver,
    IAuthenticationSchemeProvider schemeProvider)
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
            || context.IsLoginChallenge()
            || context.IsProviders()
            || context.IsToken()
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
            await RefuseAsync(context);
            return;
        }

        // A single configured provider is normally challenged directly — but not when the caller was just
        // sent back here after a failed or denied sign-in. Re-challenging immediately would race straight
        // back into the very handshake that failed (a redirect loop when the cause persists); serving the
        // page instead shows the reason and leaves the retry to the person.
        if (providers.Count > 1 || HasSignInFailureReason(context))
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
        var returnUrl = ResolveReturnUrl(context);
        var properties = TenantAuthenticationState.CreateChallengeProperties(context, tenantResolver, returnUrl);
        await context.ChallengeAsync(scheme, properties);
    }

    /// <summary>
    /// Resolves where the caller should land after signing in.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns>The resolved return URL.</returns>
    /// <remarks>
    /// Ordinarily the current request IS the destination — this middleware answers in place of
    /// whatever the caller was navigating to, so its path and query say where that was. The one
    /// exception is a request that already landed on the selection page's own path carrying an
    /// explicit <c>returnUrl</c> — the cookie authentication handler's redirect, or the invite flow,
    /// send callers there this way — in which case that query value, not the wrapper URL around it, is
    /// the real destination.
    /// </remarks>
    static string ResolveReturnUrl(HttpContext context)
    {
        if (context.Request.Path.StartsWithSegments(WellKnownPaths.LoginPage))
        {
            var explicitReturnUrl = context.Request.Query["returnUrl"].FirstOrDefault();
            if (!string.IsNullOrEmpty(explicitReturnUrl))
            {
                return explicitReturnUrl;
            }
        }

        return context.GetPathAndQuery();
    }

    /// <summary>
    /// Determines whether the caller landed on the selection page carrying a sign-in failure reason —
    /// the redirect a failed, denied, or terminated sign-in produces.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns><see langword="true"/> when a failure reason is present; otherwise <see langword="false"/>.</returns>
    static bool HasSignInFailureReason(HttpContext context) =>
        context.Request.Path.StartsWithSegments(WellKnownPaths.LoginPage)
        && context.Request.Query.ContainsKey(SignInFailureReason.QueryKey);

    /// <summary>
    /// Refuses a caller that no page can answer, naming a credential it could come back with.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns>A <see cref="Task"/> that represents the asynchronous operation.</returns>
    /// <remarks>
    /// A <c>401</c> is required to carry a <c>WWW-Authenticate</c> challenge, and the only credential this
    /// proxy accepts on the wire is a bearer token — a JWT from the configured authority, or one AuthProxy
    /// itself mints at <c>/.cratis/token</c> for a service with client credentials. The challenge is
    /// therefore emitted exactly when one of those is configured; a deployment where neither is means there
    /// is no token-based way in at all, and naming a scheme that cannot work would send a caller after
    /// credentials no endpoint would accept.
    /// </remarks>
    async Task RefuseAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;

        var bearerIsAccepted = await schemeProvider.GetSchemeAsync(JwtBearerDefaults.AuthenticationScheme) is not null
            || proxyConfig.CurrentValue.Services.Values.Any(_ => _.ClientCredentials is not null);

        if (bearerIsAccepted)
        {
            context.Response.Headers.WWWAuthenticate = "Bearer";
        }
    }
}
