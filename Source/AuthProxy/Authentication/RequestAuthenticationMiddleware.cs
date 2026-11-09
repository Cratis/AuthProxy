// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

namespace Cratis.AuthProxy.Authentication;

/// <summary>Refuses ambiguous or unsuccessful authentication on protected routes.</summary>
/// <param name="next">The next middleware in the pipeline.</param>
public class RequestAuthenticationMiddleware(RequestDelegate next)
{
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        if (IsLocalOrAnonymous(context))
        {
            await next(context);
            return;
        }

        var bearer = RequestAuthentication.HasBearer(context.Request);
        var session = RequestAuthentication.HasSession(context);
        var presented = bearer || session;
        var failed = presented && !(await context.AuthenticateAsync()).Succeeded;
        var refused = RequestAuthentication.IsAmbiguous(context);
        if (refused || failed)
        {
            if (failed && !bearer)
            {
                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }

            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers.CacheControl = "no-store";
            return;
        }

        await next(context);
    }

    static bool IsLocalOrAnonymous(HttpContext context)
    {
        var metadata = context.GetEndpoint()?.Metadata;
        var local = metadata?.GetMetadata<LocalAuthenticationEndpoint>() is not null;
        var anonymous = AnonymousPaths.IsAnonymousRoute(context) || metadata?.GetMetadata<IAllowAnonymous>() is not null;
        return local || anonymous;
    }
}
