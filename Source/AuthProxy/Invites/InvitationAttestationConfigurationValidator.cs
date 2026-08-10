// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Validates the cryptographic and endpoint configuration for signed invitation attestations.
/// </summary>
sealed class InvitationAttestationConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    const int MaximumValueLength = 2048;

    /// <summary>
    /// Validates one AuthProxy configuration instance.
    /// </summary>
    /// <param name="name">The options instance name.</param>
    /// <param name="options">The configuration to validate.</param>
    /// <returns>All configuration failures, or a successful validation result.</returns>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var invite = options.Invite;
        var attestation = invite?.Attestation;
        if (attestation is null)
        {
            return ValidateOptionsResult.Success;
        }

        var failures = new List<string>();
        ValidateAbsoluteEndpoint(invite!.StageUrl, "Invite.StageUrl", failures);
        ValidateAbsoluteEndpoint(invite.ExchangeUrl, "Invite.ExchangeUrl", failures);
        ValidateBoundedValue(attestation.Issuer, "Invite.Attestation.Issuer", failures);
        ValidateBoundedValue(attestation.Audience, "Invite.Attestation.Audience", failures);
        ValidateBoundedValue(attestation.ActiveKeyId, "Invite.Attestation.ActiveKeyId", failures);

        if (attestation.Lifetime < TimeSpan.FromSeconds(10) || attestation.Lifetime > TimeSpan.FromSeconds(60))
        {
            failures.Add("Invite.Attestation.Lifetime must be between 10 and 60 seconds.");
        }

        var duplicateKeyIds = attestation.SigningKeys
            .GroupBy(_ => _.KeyId, StringComparer.Ordinal)
            .Where(_ => _.Count() > 1)
            .Select(_ => _.Key)
            .ToArray();
        if (duplicateKeyIds.Length > 0)
        {
            failures.Add("Invite.Attestation.SigningKeys must use unique, case-sensitive key identifiers.");
        }

        foreach (var key in attestation.SigningKeys)
        {
            ValidateSigningKey(key, failures);
        }

        if (attestation.SigningKeys.Count(_ => string.Equals(_.KeyId, attestation.ActiveKeyId, StringComparison.Ordinal)) != 1)
        {
            failures.Add("Invite.Attestation.ActiveKeyId must identify exactly one configured signing key.");
        }

        if (string.IsNullOrWhiteSpace(invite.TenantClaim))
        {
            failures.Add("Invite.TenantClaim is required when signed invitation attestations are enabled.");
        }

        if (string.IsNullOrWhiteSpace(invite.EmailClaim))
        {
            failures.Add("Invite.EmailClaim is required when signed invitation attestations are enabled.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    static void ValidateAbsoluteEndpoint(string value, string path, List<string> failures)
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

    static void ValidateBoundedValue(string value, string path, List<string> failures)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > MaximumValueLength
            || !string.Equals(value, value.Trim(), StringComparison.Ordinal)
            || value.Any(char.IsControl))
        {
            failures.Add($"{path} must be nonempty, trimmed, and no longer than {MaximumValueLength} characters.");
        }
    }

    static void ValidateSigningKey(C.InvitationAttestationSigningKey key, List<string> failures)
    {
        ValidateBoundedValue(key.KeyId, "Invite.Attestation.SigningKeys.KeyId", failures);
        if (key.KeyId.Length > 128
            || key.KeyId.Any(_ => !(char.IsAsciiLetterOrDigit(_) || _ is '.' or '_' or '-')))
        {
            failures.Add("Invite.Attestation.SigningKeys.KeyId must be a bounded ASCII identifier using letters, digits, periods, underscores, or hyphens.");
        }
        if (string.IsNullOrWhiteSpace(key.PrivateKeyPem))
        {
            failures.Add("Invite.Attestation.SigningKeys.PrivateKeyPem is required.");
            return;
        }

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(key.PrivateKeyPem);
            _ = rsa.ExportParameters(true);
            if (rsa.KeySize < 2048)
            {
                failures.Add("Invite.Attestation.SigningKeys.PrivateKeyPem must contain an RSA key of at least 2048 bits.");
            }
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            failures.Add("Invite.Attestation.SigningKeys.PrivateKeyPem must contain a valid RSA private key.");
        }
    }
}
