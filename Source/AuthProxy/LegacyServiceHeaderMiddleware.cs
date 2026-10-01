// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy;

/// <summary>
/// Lets a client that still names its service in the legacy <c language="text">Service-ID</c> header be routed, by giving the
/// request the current <c language="text">x-cratis-microservice</c> header the route table matches on.
/// </summary>
/// <remarks>
/// The route table matches one header name. Normalizing here, ahead of endpoint selection, keeps it one
/// route per service instead of two, and keeps route selection and the service-level authorization that
/// reads the same request in agreement about which service was asked for. The current header is never
/// overwritten: when both are sent, the current one wins.
/// </remarks>
/// <param name="next">The next middleware in the pipeline.</param>
public class LegacyServiceHeaderMiddleware(RequestDelegate next)
{
    /// <summary>
    /// Executes the middleware for the given <paramref name="context"/>.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <returns>A <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task InvokeAsync(HttpContext context)
    {
        if (string.IsNullOrWhiteSpace(context.Request.Headers[Headers.ServiceId].FirstOrDefault())
            && ServiceSelection.FromHeaders(context.Request.Headers) is { } service)
        {
            context.Request.Headers[Headers.ServiceId] = service;
        }

        return next(context);
    }
}
