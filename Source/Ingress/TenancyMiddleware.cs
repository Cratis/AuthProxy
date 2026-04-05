// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Ingress.Configuration;
using Cratis.Ingress.Identity;
using Microsoft.Extensions.Options;

namespace Cratis.Ingress;

/// <summary>
/// Middleware that runs after authentication on every request to:
/// <list type="number">
///   <item>Strip inbound identity headers so clients cannot spoof them.</item>
///   <item>Resolve the tenant from the request and store it in <see cref="HttpContext.Items"/>.</item>
///   <item>Call <c>/.cratis/me</c> on configured microservices and write the identity cookie.</item>
/// </list>
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="config">The ingress configuration monitor.</param>
/// <param name="tenantResolver">The tenant resolver.</param>
/// <param name="identityDetailsResolver">The identity details resolver.</param>
/// <param name="logger">The logger.</param>
public class TenancyMiddleware(
    RequestDelegate next,
    IOptionsMonitor<IngressConfig> config,
    ITenantResolver tenantResolver,
    IIdentityDetailsResolver identityDetailsResolver,
    ILogger<TenancyMiddleware> logger)
{
    /// <summary>Key used to store the resolved tenant ID in <see cref="HttpContext.Items"/>.</summary>
    public const string TenantIdItemKey = "Cratis.TenantId";

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
            if (!string.IsNullOrWhiteSpace(lobbyUrl)
                && !context.Request.Path.StartsWithSegments(WellKnownPaths.InvitePathPrefix)
                && !context.Request.Cookies.ContainsKey(Cookies.InviteToken))
            {
                logger.RedirectingToLobby(context.Request.Path);
                context.Response.Redirect(lobbyUrl);
                return;
            }

            if (config.CurrentValue.TenantResolutions.Count > 0)
            {
                logger.CouldNotResolveTenant(context.Request.Path);
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }
        }

        context.Items[TenantIdItemKey] = tenantId;

        // 3. If the user is authenticated, resolve identity details (call /.cratis/me).
        var principal = context.BuildClientPrincipal();
        if (principal is not null && tenantId != Guid.Empty)
        {
            var result = await identityDetailsResolver.Resolve(context, principal, tenantId);
            if (!result.IsAuthorized)
            {
                // 403 already written by the resolver.
                return;
            }
        }

        await next(context);
    }
}
