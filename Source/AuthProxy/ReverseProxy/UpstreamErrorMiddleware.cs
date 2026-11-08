// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Telemetry;
using Yarp.ReverseProxy.Forwarder;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// Counts the requests the forwarder could not deliver to a service, by the forwarder's error type.
/// </summary>
/// <param name="next">The next middleware in the reverse proxy pipeline.</param>
public class UpstreamErrorMiddleware(RequestDelegate next)
{
    /// <summary>
    /// Runs the rest of the pipeline and records a forwarding failure if one happened.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>A task that completes when the request has been handled.</returns>
    public async Task InvokeAsync(HttpContext context)
    {
        await next(context);

        var error = context.Features.Get<IForwarderErrorFeature>()?.Error;
        if (error is not null && error != ForwarderError.None)
        {
            AuthProxyTelemetry.UpstreamFailed(error.Value);
        }
    }
}
