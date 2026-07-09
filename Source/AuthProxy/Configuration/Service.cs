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
    /// Gets or sets the registration endpoint for this service.
    /// This is currently used by the lobby configuration to identify where new users should be sent
    /// after the AuthProxy registration flow completes.
    /// </summary>
    public ServiceEndpoint? Registration { get; set; }

    /// <summary>
    /// Gets or sets whether to call the <c>/.cratis/me</c> identity endpoint on this service
    /// to enrich the identity details cookie. Defaults to <see langword="true"/> when a Backend is configured.
    /// </summary>
    public bool? ResolveIdentityDetails { get; set; }

    /// <summary>
    /// Gets or sets the back-channel client-credentials configuration for this service.
    /// When configured, AuthProxy can verify client credentials against the service and mint scoped bearer tokens.
    /// </summary>
    public ServiceClientCredentials? ClientCredentials { get; set; }
}
