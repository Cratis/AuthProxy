// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.ComponentModel.DataAnnotations;

namespace Cratis.Ingress.Configuration;

/// <summary>
/// Represents the configuration for a single OIDC provider.
/// </summary>
public class OidcProviderConfig
{
    /// <summary>
    /// Gets or sets the display name shown on the login page (e.g. "Contoso AD").
    /// </summary>
    [Required]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the provider type / brand.  Used by the login UI to select the correct logo.
    /// Defaults to <see cref="OidcProviderType.Custom"/>.
    /// </summary>
    public OidcProviderType Type { get; set; } = OidcProviderType.Custom;

    /// <summary>
    /// Gets or sets the OIDC authority URL (issuer).
    /// </summary>
    [Required]
    public string Authority { get; set; } = string.Empty;

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
    /// Gets or sets extra OAuth scopes to request (in addition to <c>openid profile email</c>).
    /// </summary>
    public IList<string> Scopes { get; set; } = [];
}
