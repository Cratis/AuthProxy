// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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
