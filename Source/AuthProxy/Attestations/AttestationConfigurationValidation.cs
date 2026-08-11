// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;

namespace Cratis.AuthProxy.Attestations;

/// <summary>
/// The shared configuration checks every AuthProxy-signed protocol applies to its signing settings.
/// </summary>
/// <remarks>
/// Signed protocols configure their own sections, so each owns its own <see cref="Microsoft.Extensions.Options.IValidateOptions{TOptions}"/>.
/// What a signing section has to prove is identical for all of them — bounded, trimmed, control-character-free
/// values that are safe to carry in a signed assertion, and RSA key material large enough to sign with — so
/// those checks live here once rather than once per protocol.
/// </remarks>
static class AttestationConfigurationValidation
{
    /// <summary>
    /// The upper bound on any single configured value that ends up inside a signed assertion.
    /// </summary>
    internal const int MaximumValueLength = 2048;

    /// <summary>
    /// Validates that a configured endpoint is an absolute HTTPS URL carrying no credentials or fragment.
    /// </summary>
    /// <param name="value">The configured value.</param>
    /// <param name="path">The configuration path reported on failure.</param>
    /// <param name="failures">The accumulated failures.</param>
    internal static void ValidateAbsoluteEndpoint(string value, string path, List<string> failures)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                && !(string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) && uri.IsLoopback))
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            failures.Add($"{path} must be an absolute HTTPS URL (HTTP is allowed only for loopback development).");
        }
    }

    /// <summary>
    /// Validates that a configured value is nonempty, trimmed, bounded and free of control characters.
    /// </summary>
    /// <param name="value">The configured value.</param>
    /// <param name="path">The configuration path reported on failure.</param>
    /// <param name="failures">The accumulated failures.</param>
    internal static void ValidateBoundedValue(string value, string path, List<string> failures)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > MaximumValueLength
            || !string.Equals(value, value.Trim(), StringComparison.Ordinal)
            || value.Any(char.IsControl))
        {
            failures.Add($"{path} must be nonempty, trimmed, and no longer than {MaximumValueLength} characters.");
        }
    }

    /// <summary>
    /// Validates one configured signing key's identifier and RSA private key material.
    /// </summary>
    /// <param name="keyId">The configured key identifier.</param>
    /// <param name="privateKeyPem">The configured PEM-encoded RSA private key.</param>
    /// <param name="path">The configuration path of the signing key collection, reported on failure.</param>
    /// <param name="failures">The accumulated failures.</param>
    internal static void ValidateSigningKey(string keyId, string privateKeyPem, string path, List<string> failures)
    {
        ValidateBoundedValue(keyId, $"{path}.KeyId", failures);
        if (string.IsNullOrEmpty(keyId)
            || keyId.Length > 128
            || keyId.Any(_ => !(char.IsAsciiLetterOrDigit(_) || _ is '.' or '_' or '-')))
        {
            failures.Add($"{path}.KeyId must be a bounded ASCII identifier using letters, digits, periods, underscores, or hyphens.");
        }
        if (string.IsNullOrWhiteSpace(privateKeyPem))
        {
            failures.Add($"{path}.PrivateKeyPem is required.");
            return;
        }

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem);
            _ = rsa.ExportParameters(true);
            if (rsa.KeySize < AttestationSigner.MinimumKeySize)
            {
                failures.Add($"{path}.PrivateKeyPem must contain an RSA key of at least {AttestationSigner.MinimumKeySize} bits.");
            }
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            failures.Add($"{path}.PrivateKeyPem must contain a valid RSA private key.");
        }
    }
}
