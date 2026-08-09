// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ErrorPages;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authorization;

/// <summary>
/// Middleware that refuses an authenticated caller who does not satisfy the claim requirements declared in
/// <see cref="C.AuthProxy.Authorization"/> or on the targeted <see cref="C.Service"/>.
/// </summary>
/// <remarks>
/// It runs directly after authorization and ahead of tenancy, identity resolution and the reverse proxy,
/// so a caller who is not allowed in is turned away before any of them run — no tenant is resolved, no
/// <c>/.cratis/me</c> call is made against a backend, and nothing is forwarded. That ordering is the whole
/// point of calling it a first gate.
/// <para>
/// The refusal is an HTML page at <c>403</c> rather than a redirect. A redirect back to the identity
/// provider is the obvious wrong answer here: the caller is already signed in and would sign in again as
/// the same person, so it loops. <c>403</c> is also a status a non-browser caller can act on, unlike the
/// <c>200</c> a provider-selection page has to be served with, so the same answer works for both and the
/// page carries the way out — signing out and coming back as someone else.
/// </para>
/// <para>
/// Skipped for anyone with no session, for the authentication endpoints themselves, and for paths a
/// service declares in <see cref="C.Service.AnonymousPaths"/>. The last is not an exemption so much as an
/// impossibility: a declared path exists precisely for callers who have no session — a webhook receiver, a
/// magic-link landing page — and a caller with no session has no claims to satisfy any requirement with,
/// so gating those paths would refuse every one of them.
/// </para>
/// </remarks>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="accessPolicy">The policy deciding whether the caller may pass.</param>
/// <param name="errorPageProvider">The error page provider used to serve the refusal page.</param>
/// <param name="logger">The logger.</param>
public class AccessControlMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.AuthProxy> config,
    IAccessPolicy accessPolicy,
    IErrorPageProvider errorPageProvider,
    ILogger<AccessControlMiddleware> logger)
{
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        var current = config.CurrentValue;

        if (!accessPolicy.IsConfigured(current)
            || context.User.Identity?.IsAuthenticated != true
            || context.IsAuthenticationBootstrap()
            || context.IsAnonymousPath(current))
        {
            await next(context);
            return;
        }

        var decision = accessPolicy.Evaluate(context, current);
        if (decision.IsGranted)
        {
            await next(context);
            return;
        }

        logger.AccessDenied(decision.UnsatisfiedClaim, SanitizePath(context.Request.Path));

        await errorPageProvider.WriteErrorPageAsync(
            context,
            WellKnownPageNames.NotAuthorized,
            StatusCodes.Status403Forbidden);
    }

    static string SanitizePath(PathString path) =>
        (path.Value ?? string.Empty).Replace('\r', '_').Replace('\n', '_');
}
