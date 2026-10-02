// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the credential AuthProxy presents to an OIDC provider's token endpoint instead of a client secret.
/// </summary>
/// <remarks>
/// Every source other than <see cref="OidcClientCredentialSource.ClientSecret"/> authenticates with a
/// <c language="text">client_assertion</c> (RFC 7523): either a JWT AuthProxy signs with a certificate, or a token the
/// platform issues (workload identity federation, managed identity). Only the properties for the selected
/// <see cref="Source"/> are read.
/// </remarks>
public class OidcClientCredential
{
    /// <summary>
    /// The default certificate store path searched for <see cref="OidcClientCredentialSource.CertificateStore"/>.
    /// </summary>
    public const string DefaultCertificateStorePath = "CurrentUser/My";

    /// <summary>
    /// Gets or sets where the credential comes from. Defaults to <see cref="OidcClientCredentialSource.ClientSecret"/>.
    /// </summary>
    public OidcClientCredentialSource Source { get; set; } = OidcClientCredentialSource.ClientSecret;

    /// <summary>
    /// Gets or sets the path of the PKCS#12 (<c language="text">.pfx</c>) file holding the certificate and its private key,
    /// for <see cref="OidcClientCredentialSource.CertificateFile"/>.
    /// </summary>
    public string CertificatePath { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the password protecting the certificate file, when it has one.
    /// </summary>
    public string CertificatePassword { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the thumbprint of the certificate to find, for <see cref="OidcClientCredentialSource.CertificateStore"/>.
    /// </summary>
    public string CertificateThumbprint { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the certificate store to search, as <c language="text">StoreLocation/StoreName</c>, for
    /// <see cref="OidcClientCredentialSource.CertificateStore"/>. Defaults to <see cref="DefaultCertificateStorePath"/>.
    /// </summary>
    public string CertificateStorePath { get; set; } = DefaultCertificateStorePath;

    /// <summary>
    /// Gets or sets the URL of the Azure Key Vault holding the certificate, for
    /// <see cref="OidcClientCredentialSource.KeyVaultCertificate"/>.
    /// </summary>
    public string KeyVaultUrl { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the name of the certificate in Azure Key Vault, for
    /// <see cref="OidcClientCredentialSource.KeyVaultCertificate"/>.
    /// </summary>
    public string KeyVaultCertificateName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the path of the file holding the federated token, for
    /// <see cref="OidcClientCredentialSource.FederatedTokenFile"/>. When empty, the file named by the
    /// <c language="text">AZURE_FEDERATED_TOKEN_FILE</c> environment variable is used. The file is re-read when the
    /// token it held expires, so a platform that rotates it is followed.
    /// </summary>
    public string TokenFilePath { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the client ID of a user-assigned managed identity. Used by
    /// <see cref="OidcClientCredentialSource.ManagedIdentity"/> to select the identity, and by
    /// <see cref="OidcClientCredentialSource.KeyVaultCertificate"/> to authenticate to Key Vault. When empty, the
    /// system-assigned identity (or, for Key Vault, the default Azure credential chain) is used.
    /// </summary>
    public string ManagedIdentityClientId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the audience of the managed identity token, for <see cref="OidcClientCredentialSource.ManagedIdentity"/>.
    /// When empty, the audience is resolved from the provider authority: <c language="text">api://AzureADTokenExchange</c> for the
    /// public cloud, and the matching value for national clouds.
    /// </summary>
    public string TokenExchangeAudience { get; set; } = string.Empty;

    /// <summary>
    /// Gets a value indicating whether the credential is presented as a <c language="text">client_assertion</c> rather than a
    /// client secret.
    /// </summary>
    public bool UsesClientAssertion => Source != OidcClientCredentialSource.ClientSecret;
}
