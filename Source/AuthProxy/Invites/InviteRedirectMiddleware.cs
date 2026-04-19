// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Middleware that runs after identity resolution to redirect the user to the lobby frontend
/// when <see cref="InviteMiddleware"/> signalled a lobby redirect via
/// <see cref="InviteMiddleware.LobbyRedirectUrlItemKey"/> in <see cref="HttpContext.Items"/>.
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
public class InviteRedirectMiddleware(RequestDelegate next)
{
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Items.TryGetValue(InviteMiddleware.LobbyRedirectUrlItemKey, out var url) && url is string redirectUrl)
        {
            context.Response.Redirect(redirectUrl);
            return;
        }

        await next(context);
    }
}
