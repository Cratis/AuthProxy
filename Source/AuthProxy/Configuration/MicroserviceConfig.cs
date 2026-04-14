// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the configuration for a single microservice that the ingress can route to.
/// </summary>
public class MicroserviceConfig
{
    /// <summary>
    /// Gets or sets the backend (API) endpoint for this microservice.
    /// </summary>
    public MicroserviceEndpointConfig? Backend { get; set; }

    /// <summary>
    /// Gets or sets the frontend (SPA / static assets) endpoint for this microservice.
    /// </summary>
    public MicroserviceEndpointConfig? Frontend { get; set; }

    /// <summary>
    /// Gets or sets whether to call the <c>/.cratis/me</c> identity endpoint on this microservice
    /// to enrich the identity details cookie. Defaults to <see langword="true"/> when a Backend is configured.
    /// </summary>
    public bool? ResolveIdentityDetails { get; set; }
}
