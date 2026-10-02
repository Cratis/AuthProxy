// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Validates the client credential of every OIDC provider at startup, so a credential that cannot work stops the host
/// with a clear message instead of failing the first sign-in.
/// </summary>
/// <param name="environment">Reads an environment variable; replaceable so the federated token default can be specified.</param>
public sealed class OidcClientCredentialConfigurationValidator(Func<string, string?> environment) : IValidateOptions<C.Authentication>
{
    /// <summary>
    /// The environment variable naming the federated token file on Kubernetes workload identity.
    /// </summary>
    public const string FederatedTokenFileEnvironmentVariable = "AZURE_FEDERATED_TOKEN_FILE";

    /// <summary>
    /// Initializes a new instance of the <see cref="OidcClientCredentialConfigurationValidator"/> class reading the
    /// process environment.
    /// </summary>
    public OidcClientCredentialConfigurationValidator()
        : this(Environment.GetEnvironmentVariable)
    {
    }

    /// <summary>
    /// Validates the client credentials of the configured OIDC providers.
    /// </summary>
    /// <param name="name">The options instance name. Validation applies identically to every name.</param>
    /// <param name="options">The authentication provider configuration to validate.</param>
    /// <returns>A successful result when every credential is usable; otherwise, every problem found.</returns>
    public ValidateOptionsResult Validate(string? name, C.Authentication options)
    {
        var failures = options.OidcProviders
            .Where(_ => _.UsesClientAssertion)
            .SelectMany(_ => Problems(_, _.ClientCredential!).Select(problem => $"OIDC provider '{_.Name}': {problem}"))
            .ToArray();

        return failures.Length == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    IEnumerable<string> Problems(C.OidcProvider provider, C.OidcClientCredential credential)
    {
        if (!string.IsNullOrEmpty(provider.ClientSecret))
        {
            yield return $"ClientSecret and a {credential.Source} ClientCredential are both configured. Configure only one credential.";
        }

        switch (credential.Source)
        {
            case C.OidcClientCredentialSource.CertificateFile when string.IsNullOrWhiteSpace(credential.CertificatePath):
                yield return "ClientCredential.CertificatePath is required for a CertificateFile credential.";
                break;

            case C.OidcClientCredentialSource.CertificateStore when string.IsNullOrWhiteSpace(credential.CertificateThumbprint):
                yield return "ClientCredential.CertificateThumbprint is required for a CertificateStore credential.";
                break;

            case C.OidcClientCredentialSource.KeyVaultCertificate:
                if (!Uri.TryCreate(credential.KeyVaultUrl, UriKind.Absolute, out var vault) || vault.Scheme != Uri.UriSchemeHttps)
                {
                    yield return "ClientCredential.KeyVaultUrl must be an absolute https URL for a KeyVaultCertificate credential.";
                }

                if (string.IsNullOrWhiteSpace(credential.KeyVaultCertificateName))
                {
                    yield return "ClientCredential.KeyVaultCertificateName is required for a KeyVaultCertificate credential.";
                }

                break;

            case C.OidcClientCredentialSource.FederatedTokenFile
                when string.IsNullOrWhiteSpace(credential.TokenFilePath)
                    && string.IsNullOrWhiteSpace(environment(FederatedTokenFileEnvironmentVariable)):
                yield return $"A FederatedTokenFile credential needs ClientCredential.TokenFilePath or the {FederatedTokenFileEnvironmentVariable} environment variable.";
                break;
        }
    }
}
