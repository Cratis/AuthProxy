// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

namespace Cratis.AuthProxy.Authentication;

/// <summary>Refuses ambiguous or unsuccessful authentication on protected routes.</summary>
/// <param name="next">The next middleware in the pipeline.</param>
public class RequestAuthenticationMiddleware(RequestDelegate next)
{
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        if (AnonymousPaths.IsAnonymousRoute(context)
            || context.GetEndpoint()?.Metadata.GetMetadata<IAllowAnonymous>() is not null)
        {
            await next(context);
            return;
        }

        var bearer = RequestAuthentication.HasBearer(context.Request);
        var session = RequestAuthentication.HasSession(context);
        var ambiguous = bearer && session;
        var presented = bearer || session;
        var failed = presented && !(await context.AuthenticateAsync()).Succeeded;
        if (ambiguous || failed)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers.CacheControl = "no-store";
            return;
        }

        await next(context);
    }
}
