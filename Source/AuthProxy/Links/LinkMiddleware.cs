// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Links;

/// <summary>
/// Middleware that initiates the session-preserving credential-linking flow.
/// <para>
/// A request to <c>/.cratis/link/{scheme}?returnUrl=…&amp;token=…</c> triggers an OAuth/OIDC challenge for
/// the requested provider — but, unlike the login flow, the resulting authentication does <em>not</em>
/// replace the primary session cookie. Instead the freshly authenticated subject is captured on the
/// provider callback and posted to the application (see
/// <see cref="AuthenticationServiceCollectionExtensions"/> <c>OnTicketReceived</c> and
/// <see cref="ILinkSubjectExchanger"/>). The link mode marker and the one-time link token travel through
/// the challenge's <see cref="AuthenticationProperties"/> so the callback can recognize the flow.
/// </para>
/// <para>
/// Linking only makes sense for an already signed-in user, so an unauthenticated request is rejected
/// rather than challenged. The <c>returnUrl</c> is constrained to a same-site relative path so the flow
/// can never be turned into an open redirect.
/// </para>
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="authConfig">The authentication configuration monitor, used to validate the requested scheme.</param>
/// <param name="logger">The logger.</param>
public class LinkMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.Authentication> authConfig,
    ILogger<LinkMiddleware> logger)
{
    /// <summary>
    /// The <see cref="AuthenticationProperties"/> item key marking a challenge as a link (rather than login) flow.
    /// </summary>
    public const string LinkModePropertyKey = "Cratis.AuthProxy.LinkMode";

    /// <summary>
    /// The <see cref="AuthenticationProperties"/> item key carrying the one-time link token through the challenge.
    /// </summary>
    public const string LinkTokenPropertyKey = "Cratis.AuthProxy.LinkToken";

    const string ApplicationRoot = "/";

    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Path.StartsWithSegments(WellKnownPaths.Link, out var remaining))
        {
            await next(context);
            return;
        }

        var scheme = remaining.Value?.TrimStart('/') ?? string.Empty;
        if (string.IsNullOrWhiteSpace(scheme) || !SchemeExists(scheme))
        {
            logger.LinkProviderNotConfigured(scheme);
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        // Linking augments an existing account, so it requires a signed-in user. An anonymous request has
        // no primary account to link to — reject it instead of starting a challenge.
        if (context.User.Identity?.IsAuthenticated != true)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var token = context.Request.Query["token"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(token))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var properties = new AuthenticationProperties
        {
            RedirectUri = ResolveReturnUrl(context.Request.Query["returnUrl"].FirstOrDefault()),
        };
        properties.Items[LinkModePropertyKey] = "true";
        properties.Items[LinkTokenPropertyKey] = token;

        logger.InitiatingLink(scheme);
        await context.ChallengeAsync(scheme, properties);
    }

    static string ResolveReturnUrl(string? returnUrl)
    {
        // The return URL is echoed back to the browser after the link completes, so it must be a same-site
        // relative path (a single leading slash, not '//') — anything else falls back to the application
        // root so the endpoint can never be used as an open redirect.
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return ApplicationRoot;
        }

        var isSafeRelative = Uri.TryCreate(returnUrl, UriKind.Relative, out _)
            && returnUrl.StartsWith('/')
            && !returnUrl.StartsWith("//", StringComparison.Ordinal);

        return isSafeRelative ? returnUrl : ApplicationRoot;
    }

    bool SchemeExists(string scheme)
    {
        var config = authConfig.CurrentValue;
        return config.OidcProviders.Any(provider => OidcProviderScheme.FromName(provider.Name) == scheme)
            || config.OAuthProviders.Any(provider => OidcProviderScheme.FromName(provider.Name) == scheme);
    }
}
