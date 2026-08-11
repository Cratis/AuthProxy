// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Links;

/// <summary>
/// Middleware that serves the session-preserving credential-linking flow.
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
/// The bare <c>/.cratis/link?token=…</c> path serves the flow's embeddable provider-selection page, and
/// <c>/.cratis/link/complete</c> the completion page a successful link ends on — see
/// <see cref="LinkFlowPages"/> for how the pages, the embedding product, and the provider window talk to
/// each other.
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

    const string CompleteSegment = "complete";

    static readonly HashSet<string> _framedDestinations = new(StringComparer.Ordinal) { "iframe", "frame", "embed", "object" };

    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Path.StartsWithSegments(WellKnownPaths.Link, out var remaining))
        {
            await next(context);
            return;
        }

        var segment = remaining.Value?.Trim('/') ?? string.Empty;

        // The completion page ends the provider window: it broadcasts the outcome to the embedding
        // selection page and closes. It carries no state and grants nothing, so whoever the callback
        // redirects here simply gets the page.
        if (string.Equals(segment, CompleteSegment, StringComparison.OrdinalIgnoreCase))
        {
            await LinkFlowPages.WriteComplete(context);
            return;
        }

        if (segment.Length > 0 && !SchemeExists(segment))
        {
            logger.LinkProviderNotConfigured(segment);
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

        // The bare link path is the flow's embeddable front door: the provider-selection page, which opens
        // the chosen provider's challenge in its own top-level window. A *framed* navigation to a specific
        // provider gets the same page instead of a challenge — the challenge redirects to the external
        // identity provider, whose pages refuse to render inside a frame, so honoring it would leave the
        // frame dead. Serving the selection page keeps the provider leg top-level by construction.
        if (segment.Length == 0 || IsFramedNavigation(context.Request))
        {
            await LinkFlowPages.WriteSelection(context);
            return;
        }

        var properties = new AuthenticationProperties
        {
            RedirectUri = ResolveReturnUrl(context.Request.Query["returnUrl"].FirstOrDefault()),
        };
        properties.Items[LinkModePropertyKey] = "true";
        properties.Items[LinkTokenPropertyKey] = token;

        logger.InitiatingLink(segment);
        await context.ChallengeAsync(segment, properties);
    }

    /// <summary>
    /// Resolves the return URL echoed back to the browser once the link completes — the flow's own
    /// completion page unless the caller asked for somewhere else.
    /// </summary>
    /// <param name="returnUrl">The caller-supplied return URL.</param>
    /// <returns>The requested target when it is same-site relative; otherwise the completion page.</returns>
    /// <remarks>
    /// See <see cref="RelativeRedirect"/> for why a single leading slash is not the whole test.
    /// </remarks>
    static string ResolveReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return WellKnownPaths.LinkComplete;
        }

        var resolved = RelativeRedirect.Resolve(returnUrl);
        return resolved == RelativeRedirect.ApplicationRoot ? WellKnownPaths.LinkComplete : resolved;
    }

    /// <summary>
    /// Determines whether the request is a navigation inside a frame, going by the browser-set
    /// <c>Sec-Fetch-Dest</c> fetch metadata header.
    /// </summary>
    /// <param name="request">The current <see cref="HttpRequest"/>.</param>
    /// <returns><see langword="true"/> when the navigation targets a frame; otherwise <see langword="false"/>.</returns>
    static bool IsFramedNavigation(HttpRequest request)
    {
        var destination = request.Headers["Sec-Fetch-Dest"].FirstOrDefault();
        return destination is not null && _framedDestinations.Contains(destination);
    }

    bool SchemeExists(string scheme)
    {
        var config = authConfig.CurrentValue;
        return config.OidcProviders.Any(provider => OidcProviderScheme.FromName(provider.Name) == scheme)
            || config.OAuthProviders.Any(provider => OidcProviderScheme.FromName(provider.Name) == scheme);
    }
}
