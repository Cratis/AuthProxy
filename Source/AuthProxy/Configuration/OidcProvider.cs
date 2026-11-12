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

    /// <summary>
    /// Gets or sets a value indicating whether the provider callback is refused unless the principal has exactly one
    /// e-mail address and the provider reports it as verified. A refusal ends like a failed sign-in and issues no session.
    /// Defaults to <see langword="false"/>.
    /// </summary>
    public bool RequireVerifiedEmail { get; set; }

    /// <summary>
    /// Gets or sets how a signed-in person whom the identity details of a service deny is answered.
    /// Defaults to <see cref="OidcDenialResponse.Forbidden"/>; <see cref="OidcDenialResponse.FailedSignIn"/> answers like a failed sign-in.
    /// </summary>
    public OidcDenialResponse DenialResponse { get; set; } = OidcDenialResponse.Forbidden;

    /// <summary>
    /// Gets or sets additional static parameters included in every authorization request to this provider.
    /// </summary>
    /// <remarks>
    /// Framework-owned OIDC parameters such as <c language="text">state</c>, <c language="text">nonce</c>, <c language="text">redirect_uri</c>, and <c language="text">client_id</c> cannot be configured here.
    /// A <c language="text">prompt</c> configured here is replaced when a fresh authentication is required.
    /// </remarks>
    public IDictionary<string, string> AuthorizationParameters { get; set; } = new Dictionary<string, string>();

    /// <summary>Gets or sets optional shorten-only browser-session settings. Null inherits the global session policy.</summary>
    public ProviderSession? Session { get; set; }
}
