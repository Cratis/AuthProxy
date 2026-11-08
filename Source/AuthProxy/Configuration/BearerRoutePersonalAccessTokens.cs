// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the personal access tokens a <see cref="BearerRoute"/> accepts.
/// </summary>
/// <remarks>
/// Declaring this makes the route recognize personal access tokens of one resource and hand them to the service
/// behind it, which is the one that verifies them. A route with no <see cref="BearerRoute.Issuers"/> accepts
/// nothing else.
/// </remarks>
public class BearerRoutePersonalAccessTokens
{
    /// <summary>
    /// Gets or sets the registered resource key the route's tokens are prefixed with: <c language="text">direct</c>,
    /// <c language="text">studio</c> or <c language="text">stage-&lt;app-key&gt;</c>. It is also the realm the route
    /// names when it accepts these tokens alone.
    /// </summary>
    public string ResourceKey { get; set; } = string.Empty;
}
