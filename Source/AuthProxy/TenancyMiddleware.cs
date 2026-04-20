// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ErrorPages;
using Cratis.AuthProxy.Tenancy;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy;

/// <summary>
/// Middleware that runs after authentication on every request to:
/// <list type="number">
///   <item>Strip inbound identity headers so clients cannot spoof them.</item>
///   <item>Resolve the tenant from the request and store it in <see cref="HttpContext.Items"/>.</item>
///   <item>Verify the resolved tenant exists (when verification is configured).</item>
/// </list>
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="tenantResolver">The tenant resolver.</param>
/// <param name="tenantVerifier">The tenant existence verifier.</param>
/// <param name="errorPageProvider">The error page provider used to serve custom error pages.</param>
/// <param name="logger">The logger.</param>
public class TenancyMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.AuthProxy> config,
    ITenantResolver tenantResolver,
    ITenantVerifier tenantVerifier,
    IErrorPageProvider errorPageProvider,
    ILogger<TenancyMiddleware> logger)
{
    /// <summary>Key used to store the resolved tenant ID in <see cref="HttpContext.Items"/>.</summary>
    public const string TenantIdItemKey = "Cratis.TenantId";

    /// <summary>
    /// Key used to store an optional strategy-specific verification URL template in
    /// <see cref="HttpContext.Items"/>.
    /// </summary>
    public const string TenantVerificationUrlTemplateItemKey = "Cratis.TenantVerificationUrlTemplate";

    /// <summary>
    /// Executes the tenancy middleware for the given <paramref name="context"/>.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns>A <see cref="Task"/> that represents the asynchronous operation.</returns>
    public async Task InvokeAsync(HttpContext context)
    {
        // 1. Always strip inbound spoofable headers before any downstream sees them.
        context.Request.Headers.Remove(Headers.Principal);
        context.Request.Headers.Remove(Headers.PrincipalId);
        context.Request.Headers.Remove(Headers.PrincipalName);
        context.Request.Headers.Remove(Headers.TenantId);

        // 2. Resolve tenant.
        if (!tenantResolver.TryResolve(context, out var tenantId))
        {
            // If a lobby is configured, redirect users without a resolved tenant to the lobby
            // frontend – unless this is an invite path (handled by InviteMiddleware) or the
            // user already has a pending invite cookie (so the Phase 2 exchange can proceed).
            var lobbyUrl = config.CurrentValue.Invite?.Lobby?.Frontend?.BaseUrl;
            var isInvitePath = context.IsInvitation();
            var hasPendingInviteCookie = context.HasPendingInvitation();
            var isAuthPath = context.IsAuthenticationUI();
            if (!string.IsNullOrWhiteSpace(lobbyUrl)
                && !isInvitePath
                && !isAuthPath
                && !hasPendingInviteCookie)
            {
                logger.RedirectingToLobby(context.Request.Path);
                context.Response.Redirect(lobbyUrl);
                return;
            }

            if (config.CurrentValue.TenantResolutions.Count > 0
                && !isAuthPath
                && !isInvitePath
                && !hasPendingInviteCookie)
            {
                logger.CouldNotResolveTenant(context.Request.Path);
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }
        }

        // 3. Verify the resolved tenant exists (when verification is configured).
        var verificationUrlTemplate = context.Items.TryGetValue(TenantVerificationUrlTemplateItemKey, out var verificationTemplate)
            ? verificationTemplate as string
            : null;

        if (!string.IsNullOrWhiteSpace(tenantId) && !await tenantVerifier.VerifyAsync(tenantId, verificationUrlTemplate))
        {
            logger.TenantDoesNotExist(tenantId, SanitizePath(context.Request.Path));
            await errorPageProvider.WriteErrorPageAsync(
                context,
                WellKnownPageNames.TenantNotFound,
                StatusCodes.Status404NotFound);
            return;
        }

        context.Items[TenantIdItemKey] = tenantId;

        await next(context);
    }

    static string SanitizePath(PathString path) =>
        (path.Value ?? string.Empty).Replace('\r', '_').Replace('\n', '_');
}
