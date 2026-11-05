// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;
using Cratis.AuthProxy.OnBehalfSessions;
using Cratis.AuthProxy.ReverseProxy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.SignInCallbacks;

/// <summary>
/// Tells a service that a returning user's session has made its first request, when the service has a sign-in callback.
/// </summary>
/// <param name="next">The next stage of the proxy pipeline.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="callbacks">The system that decides when a service is told about a user.</param>
/// <remarks>
/// Runs in the proxy pipeline, so it sees only requests that are about to be forwarded to a service, after identity
/// verification and every refusal. It never waits for the callback and never fails the request.
/// </remarks>
public class SignInCallbackMiddleware(RequestDelegate next, IOptionsMonitor<C.AuthProxy> config, ISignInCallbackDispatcher callbacks)
{
    /// <summary>
    /// Invokes the middleware.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns>An asynchronous operation.</returns>
    public async Task InvokeAsync(HttpContext context)
    {
        Report(context);
        await next(context);
    }

    static bool IsBrowserSession(HttpContext context) =>
        context.User.Identity?.IsAuthenticated == true
        && context.Features.Get<IAuthenticateResultFeature>()?.AuthenticateResult?.Ticket?.AuthenticationScheme
            == CookieAuthenticationDefaults.AuthenticationScheme;

    void Report(HttpContext context)
    {
        try
        {
            var current = config.CurrentValue;
            if (!IsBrowserSession(context)
                || context.TryGetOnBehalf(out _)
                || !current.Services.Values.Any(_ => _.SignInCallback is not null))
            {
                return;
            }

            var routed = ServiceRoutes.Resolve(context.Request, current);
            if (routed?.Service.SignInCallback is null || context.BuildClientPrincipal() is not { } principal)
            {
                return;
            }

            var tenant = context.Items.TryGetValue(TenancyMiddleware.TenantIdItemKey, out var value) ? value as string : null;
            callbacks.Returned(context, routed.Name, routed.Service, principal, tenant);
        }
        catch
        {
            // A callback must never fail the request it rides on.
        }
    }
}
