// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the authentication configuration.
/// </summary>
public class AuthenticationConfig
{
    /// <summary>
    /// Gets or sets the list of OIDC providers available for login.
    /// When more than one provider is configured the ingress redirects unauthenticated
    /// browser requests to the login selection page instead of challenging directly.
    /// </summary>
    public IList<OidcProviderConfig> OidcProviders { get; set; } = [];

    /// <summary>
    /// Gets or sets the list of regular OAuth 2.0 providers (non-OIDC) available for login.
    /// Use this for providers such as GitHub that do not expose an OIDC discovery document.
    /// </summary>
    public IList<OAuthProviderConfig> OAuthProviders { get; set; } = [];

    /// <summary>
    /// Gets the combined count of all configured authentication providers.
    /// </summary>
    public int TotalProviderCount => OidcProviders.Count + OAuthProviders.Count;
}
