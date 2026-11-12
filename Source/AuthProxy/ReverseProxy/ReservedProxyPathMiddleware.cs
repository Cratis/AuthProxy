// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// Prevents unmatched AuthProxy-owned paths from being forwarded by a service route. Only the paths in
/// <see cref="WellKnownPaths.AuthProxyOwned"/> are reserved; every other <c language="text">/.cratis/</c> path (Arc's queries,
/// commands and so on) belongs to the service and is forwarded.
/// </summary>
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
        if (!identityEndpoint && WellKnownPaths.AuthProxyOwned.Any(owned => path.StartsWithSegments(owned)))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.Response.Headers.CacheControl = "no-store";
            return;
        }

        await next(context);
    }
}
