// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ErrorPages;
using Microsoft.Extensions.Options;
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
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Path.StartsWithSegments(WellKnownPaths.OnBehalf, out var remaining))
        {
            await OnBehalfEndpoints.Handle(context, remaining, config.CurrentValue, sessions);
            return;
        }

        var resolution = await sessions.Resolve(context);
        switch (resolution.Status)
        {
            case OnBehalfResolutionStatus.Active:
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
}
