// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>Prevents unmatched AuthProxy-owned paths from being forwarded by a service route.</summary>
/// <param name="next">The remaining proxy pipeline.</param>
public class ReservedProxyPathMiddleware(RequestDelegate next)
{
    /// <summary>The route metadata identifying an explicitly matched service identity endpoint.</summary>
    internal const string IdentityEndpointMetadataKey = "Cratis.AuthProxy.ServiceIdentityEndpoint";

    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        var path = new PathString(Uri.UnescapeDataString(context.Request.Path.Value ?? string.Empty));
        var identityEndpoint = context.GetReverseProxyFeature().Route.Config.Metadata
            ?.GetValueOrDefault(IdentityEndpointMetadataKey) == bool.TrueString;
        if (path.StartsWithSegments(WellKnownPaths.Cratis) && !identityEndpoint)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.Response.Headers.CacheControl = "no-store";
            return;
        }

        await next(context);
    }
}
