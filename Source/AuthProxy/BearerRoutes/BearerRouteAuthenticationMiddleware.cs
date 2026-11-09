// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>Refuses a failed issued-token handoff before any browser-oriented middleware can answer.</summary>
/// <param name="next">The next middleware.</param>
/// <param name="config">The configured bearer routes.</param>
public class BearerRouteAuthenticationMiddleware(RequestDelegate next, IOptionsMonitor<C.AuthProxy> config)
{
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        if (BearerRouteTable.TryMatch(context.Request.Path, config.CurrentValue, out var route))
        {
            var result = await context.AuthenticateAsync();
            if (!result.Succeeded)
            {
                BearerChallenge.Write(context, BearerTokenValidation.Refused(BearerTokenValidationStatus.Invalid, "client-credentials authentication failed"), route);
                return;
            }
        }

        await next(context);
    }
}
