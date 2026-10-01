// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.ComponentModel.DataAnnotations;

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the configuration for a single OIDC provider.
/// </summary>
public class OidcProvider
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
    /// <remarks>
    /// Leave empty when <see cref="ClientCredential"/> selects a certificate or federated credential.
    /// </remarks>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the credential AuthProxy presents to the provider's token endpoint instead of
    /// <see cref="ClientSecret"/>: a certificate (file, certificate store or Azure Key Vault) or a federated
    /// credential (workload identity token file or Azure managed identity).
    /// When absent, <see cref="ClientSecret"/> is used.
    /// </summary>
    public OidcClientCredential? ClientCredential { get; set; }

    /// <summary>
    /// Gets a value indicating whether the provider authenticates to its token endpoint with a client assertion.
    /// </summary>
    public bool UsesClientAssertion => ClientCredential?.UsesClientAssertion == true;

    /// <summary>
    /// Gets or sets extra OAuth scopes to request (in addition to <c language="text">openid profile email</c>).
    /// </summary>
    public IList<string> Scopes { get; set; } = [];

    /// <summary>
    /// Gets or sets how the provider returns the authorization code to the callback endpoint.
    /// Defaults to <see cref="OidcResponseMode.Query"/>, which keeps the handshake cookies SameSite=Lax;
    /// see <see cref="OidcResponseMode.FormPost"/> for providers that mandate a form POST callback.
    /// </summary>
    public OidcResponseMode ResponseMode { get; set; } = OidcResponseMode.Query;

    /// <summary>
    /// Gets or sets the optional canonical federated identity contract for this provider.
    /// When absent, the provider retains the legacy claim-selection and forwarding behavior.
    /// </summary>
    public CanonicalIdentity? CanonicalIdentity { get; set; }
}
