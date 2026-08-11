// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.ReverseProxy;
using Yarp.ReverseProxy.Model;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// The last check before a request is handed to the reverse proxy: a proxied request either carries a
/// forwardable identity or is not proxied at all. An authenticated session whose principal can no longer
/// be built is terminated and sent back to provider selection instead of being forwarded without identity
/// headers.
/// </summary>
/// <remarks>
/// Authorization guarantees that a non-anonymous proxied route is only reached by an authenticated caller —
/// but "authenticated" is the cookie's verdict, and building the forwardable <see cref="ClientPrincipal"/>
/// can still fail closed (canonical identity resolution refuses the session, configuration changed under
/// it). Without this guard such a request is proxied with <em>no</em> identity headers, the backend refuses
/// everything, and the person stares at an application that renders nothing while being "signed in".
/// Terminating the session is the honest answer: the very next navigation lands on provider selection with
/// a reason the page can show, and a fresh sign-in produces a session that works. Routes the service
/// declared anonymous are exempt — they are proxied without identity by design.
/// </remarks>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="logger">The logger.</param>
public class IdentityForwardingGuardMiddleware(RequestDelegate next, ILogger<IdentityForwardingGuardMiddleware> logger)
{
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.GetEndpoint()?.Metadata.GetMetadata<RouteModel>() is not { } route
            || IsAnonymousRoute(route)
            || context.User.Identity?.IsAuthenticated != true
            || context.BuildClientPrincipal() is not null)
        {
            await next(context);
            return;
        }

        logger.TerminatingUnforwardableSession(RequestPathRedaction.Redact(context.Request.Path));
        await SessionTermination.SignOutAndClearCookies(context);

        // A person navigating gets the provider-selection page with a reason and their destination
        // preserved; every other caller gets a status it can act on — never a silently forwarded,
        // identity-less request.
        if (context.IsDocumentNavigation())
        {
            var returnUrl = RelativeRedirect.Resolve(context.GetPathAndQuery());
            context.Response.Redirect(
                $"{WellKnownPaths.LoginPage}?{SignInFailureReason.QueryKey}={SignInFailureReason.InvalidSession}&returnUrl={Uri.EscapeDataString(returnUrl)}");
            return;
        }

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
    }

    static bool IsAnonymousRoute(RouteModel route) =>
        string.Equals(
            route.Config.AuthorizationPolicy,
            MicroserviceReverseProxyConfigProvider.AnonymousAuthorizationPolicy,
            StringComparison.OrdinalIgnoreCase);
}
