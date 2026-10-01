// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Model;

namespace Cratis.AuthProxy;

/// <summary>
/// Reads which service a request names in its headers.
/// </summary>
/// <remarks>
/// Arc names it <see cref="Headers.ServiceId"/>; earlier AuthProxy releases named it
/// <see cref="Headers.LegacyServiceId"/>. Both are accepted so an existing client keeps working, and the
/// current name wins when a request carries both. The <c language="text">service</c> query parameter is a separate fallback the
/// callers apply themselves.
/// </remarks>
static class ServiceSelection
{
    /// <summary>
    /// The route metadata entry identifying the configured service.
    /// </summary>
    internal const string RouteMetadataKey = "Cratis.AuthProxy.Service";

    /// <summary>
    /// Gets the service selected by the reverse-proxy route, independent of caller-supplied selectors.
    /// </summary>
    /// <param name="context">The routed request.</param>
    /// <returns>The selected service, or <see langword="null"/> for a non-proxy endpoint.</returns>
    public static string? FromRoute(HttpContext context) =>
        context.GetEndpoint()?.Metadata.GetMetadata<RouteModel>()?.Config.Metadata is { } metadata
        && metadata.TryGetValue(RouteMetadataKey, out var service) ? service : null;

    /// <summary>
    /// Gets the service named by the request headers.
    /// </summary>
    /// <param name="headers">The request headers.</param>
    /// <returns>The first non-blank value of the current header, then of the legacy header; otherwise <see langword="null"/>.</returns>
    public static string? FromHeaders(IHeaderDictionary headers)
    {
        var current = headers[Headers.ServiceId].FirstOrDefault();
        return !string.IsNullOrWhiteSpace(current)
            ? current
            : headers[Headers.LegacyServiceId].FirstOrDefault() is { } legacy && !string.IsNullOrWhiteSpace(legacy)
                ? legacy
                : null;
    }
}
