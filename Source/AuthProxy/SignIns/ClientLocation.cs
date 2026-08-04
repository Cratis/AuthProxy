// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignIns;

/// <summary>
/// Represents the approximate origin of a request — the resolved client IP address and a best-effort,
/// human-readable location derived from it.
/// </summary>
/// <param name="IpAddress">The resolved client IP address, honoring <c>X-Forwarded-For</c>. Empty when it cannot be resolved.</param>
/// <param name="Location">
/// A best-effort, coarse location string (for example <c>"San Francisco, California, US"</c> or <c>"US"</c>),
/// assembled from geo headers a fronting CDN/proxy may add. Empty when no geo information is available.
/// </param>
public record ClientLocation(string IpAddress, string Location)
{
    /// <summary>
    /// Represents an unknown <see cref="ClientLocation"/> with no IP address or location.
    /// </summary>
    public static readonly ClientLocation Unknown = new(string.Empty, string.Empty);
}
