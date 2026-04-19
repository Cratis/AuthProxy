// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ErrorPages;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Middleware that resolves identity details for every authenticated request:
/// enriches the principal, calls <c>/.cratis/me</c> on configured services, and
/// writes the result to the <c>.cratis-identity</c> response cookie.
/// Skips immediately when the cookie is already present (cached from a previous request).
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="identityDetailsResolver">The identity details resolver.</param>
/// <param name="errorPageProvider">The error page provider used to serve custom error pages.</param>
public class IdentityMiddleware(
    RequestDelegate next,
    IIdentityDetailsResolver identityDetailsResolver,
    IErrorPageProvider errorPageProvider)
{
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        var principal = context.BuildClientPrincipal();
        var tenantId = context.Items.TryGetValue(TenancyMiddleware.TenantIdItemKey, out var t) ? t as string : null;

        if (principal is not null && !string.IsNullOrWhiteSpace(tenantId))
        {
            var result = await identityDetailsResolver.Resolve(context, principal, tenantId);
            if (!result.IsAuthorized)
            {
                await errorPageProvider.WriteErrorPageAsync(
                    context,
                    WellKnownPageNames.Forbidden,
                    StatusCodes.Status403Forbidden);
                return;
            }
        }

        await next(context);
    }
}
