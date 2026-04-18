// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the configuration for a single service that the auth proxy can route to.
/// </summary>
public class Service
{
    /// <summary>
    /// Gets or sets the backend (API) endpoint for this service.
    /// </summary>
    public ServiceEndpoint? Backend { get; set; }

    /// <summary>
    /// Gets or sets the frontend (SPA / static assets) endpoint for this service.
    /// </summary>
    public ServiceEndpoint? Frontend { get; set; }

    /// <summary>
    /// Gets or sets whether to call the <c>/.cratis/me</c> identity endpoint on this service
    /// to enrich the identity details cookie. Defaults to <see langword="true"/> when a Backend is configured.
    /// </summary>
    public bool? ResolveIdentityDetails { get; set; }
}
