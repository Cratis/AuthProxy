// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Identity.Abstractions;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Maps an AuthProxy <see cref="C.OidcClientCredential"/> onto the <see cref="CredentialDescription"/> model of
/// Microsoft.Identity.Web, whose credential loaders do the platform work (certificate stores, Key Vault, workload
/// identity token files and managed identity).
/// </summary>
static class OidcClientCredentialDescription
{
    /// <summary>
    /// Creates the credential description for a client-assertion credential.
    /// </summary>
    /// <param name="credential">The configured credential. Its source must use a client assertion.</param>
    /// <param name="authority">The provider authority used to resolve the managed-identity token-exchange audience.</param>
    /// <returns>The <see cref="CredentialDescription"/> the credential loader loads.</returns>
    /// <exception cref="OidcClientCredentialUnavailable">The source does not use a client assertion.</exception>
    internal static CredentialDescription From(C.OidcClientCredential credential, string authority) => credential.Source switch
    {
        C.OidcClientCredentialSource.CertificateFile => new()
        {
            SourceType = CredentialSource.Path,
            CertificateDiskPath = credential.CertificatePath,
            CertificatePassword = NullIfEmpty(credential.CertificatePassword)
        },
        C.OidcClientCredentialSource.CertificateStore => new()
        {
            SourceType = CredentialSource.StoreWithThumbprint,
            CertificateStorePath = string.IsNullOrWhiteSpace(credential.CertificateStorePath)
                ? C.OidcClientCredential.DefaultCertificateStorePath
                : credential.CertificateStorePath,
            CertificateThumbprint = credential.CertificateThumbprint
        },
        C.OidcClientCredentialSource.KeyVaultCertificate => new()
        {
            SourceType = CredentialSource.KeyVault,
            KeyVaultUrl = credential.KeyVaultUrl,
            KeyVaultCertificateName = credential.KeyVaultCertificateName,
            ManagedIdentityClientId = NullIfEmpty(credential.ManagedIdentityClientId)
        },
        C.OidcClientCredentialSource.FederatedTokenFile => new()
        {
            SourceType = CredentialSource.SignedAssertionFilePath,
            SignedAssertionFileDiskPath = NullIfEmpty(credential.TokenFilePath)
        },
        C.OidcClientCredentialSource.ManagedIdentity => new()
        {
            SourceType = CredentialSource.SignedAssertionFromManagedIdentity,
            ManagedIdentityClientId = NullIfEmpty(credential.ManagedIdentityClientId),
            TokenExchangeUrl = NullIfEmpty(credential.TokenExchangeAudience) ?? TokenExchangeAudienceOf(authority)
        },
        _ => throw new OidcClientCredentialUnavailable($"The client credential source '{credential.Source}' does not use a client assertion.")
    };

    static string TokenExchangeAudienceOf(string authority) => Uri.TryCreate(authority, UriKind.Absolute, out var uri)
        ? uri.Host.ToLowerInvariant() switch
        {
            "login.microsoftonline.us" => "api://AzureADTokenExchangeUSGov",
            "login.chinacloudapi.cn" => "api://AzureADTokenExchangeChina",
            _ => "api://AzureADTokenExchange"
        }
        : "api://AzureADTokenExchange";

    static string? NullIfEmpty(string value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
