// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ErrorPages;
using Cratis.AuthProxy.OnBehalfSessions;
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
        // Every x-ms-client-principal* header and the tenant under both of its names; only the tenant this
        // middleware resolves below is ever forwarded.
        SpoofableHeaders.Strip(context.Request.Headers);
        context.Request.Headers.Remove(Headers.TokenClientId);
        context.Request.Headers.Remove(Headers.TokenScope);

        // 2. Resolve tenant. An on-behalf session acts in the tenant its grant was confirmed for, whatever the actor's
        // own claims or selection say — but never in a tenant the request itself addresses differently.
        string tenantId;
        if (context.TryGetOnBehalf(out var onBehalf))
        {
            if (AddressesAnotherTenant(context, onBehalf.Session.Tenant))
            {
                logger.OnBehalfTenantConflict(RequestPathRedaction.Redact(context.Request.Path));
                await errorPageProvider.WriteErrorPageAsync(context, WellKnownPageNames.Forbidden, StatusCodes.Status403Forbidden);
                return;
            }

            tenantId = onBehalf.Session.Tenant;
        }
        else if (!tenantResolver.TryResolve(context, out tenantId))
        {
            // If a lobby is configured, redirect users without a resolved tenant to the lobby
            // frontend – unless this is an invite path (handled by InviteMiddleware) or the
            // user already has a pending invite cookie (so the Phase 2 exchange can proceed).
            var lobbyUrl = config.CurrentValue.Invite?.Lobby?.Frontend?.BaseUrl;
            var shouldRedirectToLobby = config.CurrentValue.Invite?.RedirectToLobbyWhenTenantUnresolved == true;
            var isInvitePath = context.IsInvitation();
            var isRegistrationPath = context.IsRegistration();
            var hasPendingInviteCookie = context.HasPendingInvitation();
            var hasPendingRegistrationCookie = context.HasPendingRegistration();
            var isAuthPath = context.IsAuthenticationUI();

            // A caller on a declared anonymous path has no session to resolve a tenant from, so treat it
            // like the other tenant-less paths below. Without this, declaring a path anonymous would move
            // the refusal from SelectProviderMiddleware to here instead of removing it.
            var isAnonymousPath = context.IsAnonymousPath(config.CurrentValue);

            if (shouldRedirectToLobby
                && !string.IsNullOrWhiteSpace(lobbyUrl)
                && !isInvitePath
                && !isRegistrationPath
                && !isAuthPath
                && !isAnonymousPath
                && !hasPendingInviteCookie
                && !hasPendingRegistrationCookie)
            {
                logger.RedirectingToLobby(context.Request.Path);
                context.Response.Redirect(lobbyUrl);
                return;
            }

            if (config.CurrentValue.TenantResolutions.Count > 0
                && !isAuthPath
                && !isInvitePath
                && !isRegistrationPath
                && !isAnonymousPath
                && !hasPendingInviteCookie
                && !hasPendingRegistrationCookie)
            {
                logger.CouldNotResolveTenant(context.Request.Path);

                // An authenticated user with no resolvable tenant is signed in but not associated
                // with any organization. Serve a specific 403 page explaining this rather than a
                // bare 401, which a frontend would otherwise treat as "not signed in" and loop back
                // to the login flow.
                if (context.User.Identity?.IsAuthenticated == true)
                {
                    await errorPageProvider.WriteErrorPageAsync(
                        context,
                        WellKnownPageNames.NoOrganization,
                        StatusCodes.Status403Forbidden);
                    return;
                }

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
            logger.TenantDoesNotExist(tenantId, RequestPathRedaction.Redact(context.Request.Path));
            await errorPageProvider.WriteErrorPageAsync(
                context,
                WellKnownPageNames.TenantNotFound,
                StatusCodes.Status404NotFound);
            return;
        }

        context.Items[TenantIdItemKey] = tenantId;

        await next(context);
    }

    /// <summary>
    /// Determines whether the request addresses a tenant other than the on-behalf session's.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="sessionTenant">The tenant the on-behalf session acts in.</param>
    /// <returns><see langword="true"/> when the request names another tenant through its host, route or the deployment's fixed tenant.</returns>
    /// <remarks>
    /// A tenant taken from the request's address or fixed by the deployment is a statement about where the request
    /// goes, and an on-behalf session must not be carried there. A tenant taken from the actor's own claims or
    /// selection, or a fallback default, is only a statement about the actor, and the session's tenant replaces it.
    /// </remarks>
    bool AddressesAnotherTenant(HttpContext context, string sessionTenant) =>
        tenantResolver.TryResolve(context, out TenantResolutionResult resolution)
        && resolution.Strategy is C.TenantSourceIdentifierResolverType.Host
            or C.TenantSourceIdentifierResolverType.SubHost
            or C.TenantSourceIdentifierResolverType.Route
            or C.TenantSourceIdentifierResolverType.Specified
        && !string.IsNullOrWhiteSpace(resolution.TenantId)
        && !string.Equals(resolution.TenantId, sessionTenant, StringComparison.OrdinalIgnoreCase);
}
