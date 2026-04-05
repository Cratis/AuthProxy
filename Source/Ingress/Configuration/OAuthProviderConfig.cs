// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.ComponentModel.DataAnnotations;

namespace Cratis.Ingress.Configuration;

/// <summary>
/// Represents the configuration for a regular OAuth 2.0 provider (non-OIDC) such as GitHub.
/// Unlike OIDC providers, OAuth providers require explicit endpoint URLs instead of an authority discovery document.
/// </summary>
public class OAuthProviderConfig
{
    /// <summary>
    /// Gets or sets the display name shown on the login page (e.g. "GitHub").
    /// </summary>
    [Required]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the provider type / brand.  Used by the login UI to select the correct logo.
    /// Defaults to <see cref="OidcProviderType.Custom"/>.
    /// </summary>
    public OidcProviderType Type { get; set; } = OidcProviderType.Custom;

    /// <summary>
    /// Gets or sets the OAuth 2.0 authorization endpoint URL.
    /// </summary>
    [Required]
    public string AuthorizationEndpoint { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the OAuth 2.0 token endpoint URL.
    /// </summary>
    [Required]
    public string TokenEndpoint { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the URL of the user-information (profile) API endpoint.
    /// </summary>
    [Required]
    public string UserInformationEndpoint { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the OAuth client ID registered with the provider.
    /// </summary>
    [Required]
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the OAuth client secret.
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets extra OAuth scopes to request in addition to provider defaults.
    /// </summary>
    public IList<string> Scopes { get; set; } = [];

    /// <summary>
    /// Gets or sets the claim mappings from the user-info JSON response.
    /// Key is the claim type (e.g. <c>ClaimTypes.Name</c> or a custom URN);
    /// value is the JSON field name in the user-info response (e.g. <c>login</c>).
    /// </summary>
    public IDictionary<string, string> ClaimMappings { get; set; } = new Dictionary<string, string>();
}
