// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Represents a configured bearer route with its path prefix normalized and its defaults applied.
/// </summary>
/// <param name="ServiceName">The name of the service the route belongs to.</param>
/// <param name="BackendBaseUrl">The base URL of the service backend the route is forwarded to.</param>
/// <param name="Prefix">The normalized path prefix.</param>
/// <param name="Issuers">The issuers whose tokens the route accepts.</param>
/// <param name="Route">The route configuration.</param>
/// <param name="ResourceMetadataUrl">The protected-resource metadata URL named in challenges, when configured.</param>
/// <param name="ResourceMetadataPath">The normalized path of <paramref name="ResourceMetadataUrl"/>, when configured.</param>
public sealed record ResolvedBearerRoute(
    string ServiceName,
    string BackendBaseUrl,
    string Prefix,
    IReadOnlyList<ResolvedBearerIssuer> Issuers,
    C.BearerRoute Route,
    Uri? ResourceMetadataUrl,
    string? ResourceMetadataPath)
{
    /// <summary>
    /// Gets the clock skew allowed when validating a token lifetime on this route, never more than
    /// <see cref="C.BearerRoute.MaximumClockSkew"/> and never negative.
    /// </summary>
    public TimeSpan ClockSkew => Route.ClockSkew switch
    {
        null => C.BearerRoute.DefaultClockSkew,
        { } skew when skew < TimeSpan.Zero => TimeSpan.Zero,
        { } skew when skew > C.BearerRoute.MaximumClockSkew => C.BearerRoute.MaximumClockSkew,
        { } skew => skew,
    };

    /// <summary>
    /// Gets the token claim the tenant is read from.
    /// </summary>
    public string TenantClaimType => string.IsNullOrWhiteSpace(Route.TenantClaimType)
        ? C.BearerRoute.DefaultTenantClaimType
        : Route.TenantClaimType;

    /// <summary>
    /// Gets the identity provider label of the forwarded principal.
    /// </summary>
    public string IdentityProvider => string.IsNullOrWhiteSpace(Route.IdentityProvider)
        ? C.BearerRoute.DefaultIdentityProvider
        : Route.IdentityProvider;
}
