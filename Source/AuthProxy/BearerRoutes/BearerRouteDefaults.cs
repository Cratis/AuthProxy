// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Defines constants used by bearer routes.
/// </summary>
public static class BearerRouteDefaults
{
    /// <summary>
    /// The name of the HTTP client used to read issuer metadata and signing keys.
    /// </summary>
    public const string MetadataHttpClientName = "Cratis.AuthProxy.BearerRoutes.Metadata";

    /// <summary>
    /// The JWT signing algorithms accepted on a bearer route. Symmetric algorithms and <c language="text">none</c> are
    /// never accepted.
    /// </summary>
    public static readonly IReadOnlyList<string> AllowedAlgorithms = ["RS256", "ES256"];

    /// <summary>
    /// The <see cref="HttpContext.Items"/> key holding the <see cref="BearerForwardedIdentity"/> of a request
    /// authenticated on a bearer route. Absent for everything else, including a protected-resource metadata request.
    /// </summary>
    internal const string ForwardedIdentityItemKey = "Cratis.AuthProxy.BearerRoutes.ForwardedIdentity";
}
