// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ErrorPages;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Middleware that resolves identity details for every authenticated request:
/// enriches the principal, calls <c>/.cratis/me</c> on configured services, and
/// writes the result to the <c>.cratis-identity</c> response cookie.
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="identityDetailsResolver">The identity details resolver.</param>
/// <param name="errorPageProvider">The error page provider used to serve custom error pages.</param>
/// <remarks>
/// Resolution is keyed by principal <em>and</em> tenant, so it needs both. While the call was enrichment
/// only, having no tenant to ask about meant there was nothing to enrich with and skipping was harmless.
/// Once a service's answer is an authorization decision it stops being harmless: skipping the call skips the
/// decision, and the request is forwarded to the application with nobody having said the caller may be
/// there. A deployment that requires verification therefore refuses a tenant-less authenticated request
/// rather than passing it on — see <see cref="MustBeVerified"/> for the paths that are exempt and why.
/// </remarks>
public class IdentityMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.AuthProxy> config,
    IIdentityDetailsResolver identityDetailsResolver,
    IErrorPageProvider errorPageProvider)
{
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        var principal = context.BuildClientPrincipal();
        var tenantId = context.Items.TryGetValue(TenancyMiddleware.TenantIdItemKey, out var t) ? t as string : null;

        if (principal is not null)
        {
            var current = config.CurrentValue;

            if (string.IsNullOrWhiteSpace(tenantId))
            {
                if (MustBeVerified(context, current))
                {
                    await Refuse(context);
                    return;
                }
            }
            else
            {
                var result = await identityDetailsResolver.Resolve(context, principal, tenantId);
                if (!result.IsAuthorized)
                {
                    await Refuse(context);
                    return;
                }
            }
        }

        await next(context);
    }

    /// <summary>
    /// Determines whether an authenticated request that resolved no tenant must be refused.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="config">The current configuration.</param>
    /// <returns><see langword="true"/> when the request must be refused; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Only a deployment that requires verification refuses here. Under enrichment there is nothing to
    /// enforce, and refusing would break every tenant-less flow for no gain.
    /// <para>
    /// Two kinds of path are exempt even then. A path a service declares in
    /// <see cref="C.Service.AnonymousPaths"/> is declared to be served without a session at all, so
    /// demanding an identity verdict for it would contradict the declaration that put it there — this is the
    /// one deliberate exemption, and it is documented as such. AuthProxy's own authentication, invite and
    /// registration surfaces are exempt because they are answered by AuthProxy and never forwarded to a
    /// service: a signed-in caller with no organization has to be able to reach the provider selection page
    /// to sign in somewhere else, and refusing there would strand them.
    /// </para>
    /// <para>
    /// Everything else is refused, including the ordinary application paths a tenant-less request can still
    /// reach — most notably one carrying a pending-invite or pending-registration cookie, which suppresses
    /// the tenancy refusal for the benefit of the onboarding exchange and does not stop the request being
    /// forwarded when that exchange does not claim it.
    /// </para>
    /// </remarks>
    static bool MustBeVerified(HttpContext context, C.AuthProxy config) =>
        config.RequiresIdentityVerification
        && !context.IsAnonymousPath(config)
        && !context.IsAuthenticationUI()
        && !context.IsInvitation()
        && !context.IsRegistration();

    Task Refuse(HttpContext context) =>
        errorPageProvider.WriteErrorPageAsync(
            context,
            WellKnownPageNames.Forbidden,
            StatusCodes.Status403Forbidden);
}
