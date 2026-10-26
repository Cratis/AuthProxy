// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ErrorPages;
using Cratis.AuthProxy.ReverseProxy;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Model;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Answers AuthProxy's on-behalf endpoints and puts the on-behalf session, when there is one, on every other request.
/// </summary>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="sessions">The on-behalf sessions.</param>
/// <param name="errorPageProvider">The error page provider.</param>
/// <remarks>
/// It runs after authentication and the deployment's own authorization gates, so the actor has to be allowed in as
/// themselves before they can act as anybody, and before tenancy and identity resolution, so both see the
/// represented user. The endpoints are:
/// <list type="bullet">
///   <item><c language="text">POST /.cratis/on-behalf/start</c> with a JSON body — see <see cref="OnBehalfEndpoints"/>.</item>
///   <item><c language="text">POST /.cratis/on-behalf/end</c>.</item>
///   <item><c language="text">GET /.cratis/on-behalf</c>, describing the current session.</item>
/// </list>
/// A request whose session has ended, or whose grant cannot be re-checked, is refused — never forwarded as the actor
/// instead, which would quietly change who the application believes is acting halfway through somebody's work.
/// </remarks>
public class OnBehalfMiddleware(
    RequestDelegate next,
    IOptionsMonitor<C.AuthProxy> config,
    IOnBehalfSessions sessions,
    IErrorPageProvider errorPageProvider)
{
    /// <summary>
    /// The <see cref="Headers.OnBehalfRefused"/> value for a request routed to a service the session may not reach.
    /// </summary>
    public const string ServiceNotPermitted = "service-not-permitted";

    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Path.StartsWithSegments(WellKnownPaths.OnBehalf, out var remaining))
        {
            await OnBehalfEndpoints.Handle(context, remaining, config.CurrentValue, sessions);
            return;
        }

        if (EntersIdentityFlow(context))
        {
            // Invitations, registrations and account links act on the signed-in person's own account. Carrying the
            // represented user into one would accept an invitation, register or link an account as them, so the
            // session ends and the flow goes on as the actor.
            if (context.Request.Cookies.ContainsKey(Cookies.OnBehalf))
            {
                await sessions.End(context, OnBehalfSessionEndReason.IdentityFlowStarted);
                context.Response.Headers[Headers.OnBehalfEnded] = OnBehalfSessionEndReason.IdentityFlowStarted.ToWireValue();
            }

            await next(context);
            return;
        }

        var resolution = await sessions.Resolve(context);
        switch (resolution.Status)
        {
            case OnBehalfResolutionStatus.Active:
                if (!ReachesPermittedService(context, config.CurrentValue))
                {
                    // The represented user's identity is never sent anywhere the session was not granted for. The
                    // session itself goes on: following a link into another service is not a reason to end it.
                    context.Response.Headers[Headers.OnBehalfRefused] = ServiceNotPermitted;
                    await errorPageProvider.WriteErrorPageAsync(context, WellKnownPageNames.Forbidden, StatusCodes.Status403Forbidden);
                    return;
                }

                context.SetOnBehalf(resolution.Context!);
                break;

            case OnBehalfResolutionStatus.Ended:
                context.Response.Headers[Headers.OnBehalfEnded] = resolution.Reason!.Value.ToWireValue();
                await errorPageProvider.WriteErrorPageAsync(context, WellKnownPageNames.Forbidden, StatusCodes.Status403Forbidden);
                return;

            case OnBehalfResolutionStatus.Unavailable:
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                return;
        }

        await next(context);
    }

    /// <summary>
    /// Determines whether a request is part of an invitation, registration or account-link flow.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns><see langword="true"/> when the request enters or continues one of those flows.</returns>
    static bool EntersIdentityFlow(HttpContext context) =>
        context.IsInvitation()
        || context.IsRegistration()
        || context.Request.Path.StartsWithSegments(WellKnownPaths.Link)
        || context.HasPendingInvitation()
        || context.HasPendingRegistration();

    /// <summary>
    /// Determines whether a request stays within the services an on-behalf session may reach.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="config">The current configuration.</param>
    /// <returns><see langword="true"/> when nothing is forwarded, or it is forwarded to a permitted service.</returns>
    /// <remarks>
    /// Endpoint routing has already selected the proxy route, and its cluster is what the request is forwarded to. A
    /// request no proxy route selected is answered by AuthProxy itself and reaches no service. A proxy route whose
    /// service cannot be resolved is refused: not knowing where the identity goes is not a reason to send it.
    /// </remarks>
    static bool ReachesPermittedService(HttpContext context, C.AuthProxy config)
    {
        if (context.GetEndpoint()?.Metadata.GetMetadata<RouteModel>() is null)
        {
            return true;
        }

        return config.OnBehalf?.Permits(ServiceRoutes.Resolve(context.Request, config)?.Name) == true;
    }
}
