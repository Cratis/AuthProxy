// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Defines how AuthProxy authenticates itself to an OIDC provider's token endpoint.
/// </summary>
public enum OidcClientCredentialSource
{
    /// <summary>
    /// The provider's <see cref="OidcProvider.ClientSecret"/> is sent as <c language="text">client_secret</c>.
    /// This is the default and the behavior of providers that configure no client credential.
    /// </summary>
    ClientSecret = 0,

    /// <summary>
    /// A certificate with a private key, loaded from a PKCS#12 (<c language="text">.pfx</c>) file, signs a
    /// <c language="text">private_key_jwt</c> client assertion.
    /// </summary>
    CertificateFile = 1,

    /// <summary>
    /// A certificate with a private key, found by thumbprint in an operating-system certificate store, signs a
    /// <c language="text">private_key_jwt</c> client assertion.
    /// </summary>
    CertificateStore = 2,

    /// <summary>
    /// A certificate with a private key, downloaded from Azure Key Vault, signs a
    /// <c language="text">private_key_jwt</c> client assertion.
    /// </summary>
    KeyVaultCertificate = 3,

    /// <summary>
    /// A platform-issued federated token read from a file (Kubernetes workload identity, by default the file named
    /// by <c language="text">AZURE_FEDERATED_TOKEN_FILE</c>) is sent as the client assertion.
    /// </summary>
    FederatedTokenFile = 4,

    /// <summary>
    /// An Azure managed identity token for the token-exchange audience is sent as the client assertion, so no
    /// secret or certificate exists to rotate.
    /// </summary>
    ManagedIdentity = 5,
}
