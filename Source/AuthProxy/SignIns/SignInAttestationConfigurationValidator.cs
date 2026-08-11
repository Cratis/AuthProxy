// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Attestations;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.SignIns;

/// <summary>
/// Validates the cryptographic and endpoint configuration for signed sign-in notifications.
/// </summary>
/// <remarks>
/// A signing deployment fails closed at run time — an unusable key means no notification is posted at all — so
/// the failure a deployer must never discover from missing sign-in records is caught here, at startup.
/// </remarks>
sealed class SignInAttestationConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <summary>
    /// Validates one AuthProxy configuration instance.
    /// </summary>
    /// <param name="name">The options instance name.</param>
    /// <param name="options">The configuration to validate.</param>
    /// <returns>All configuration failures, or a successful validation result.</returns>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var signIn = options.SignIn;
        var attestation = signIn?.Attestation;
        if (attestation is null)
        {
            return ValidateOptionsResult.Success;
        }

        var failures = new List<string>();
        AttestationConfigurationValidation.ValidateAbsoluteEndpoint(signIn!.NotifyUrl, "SignIn.NotifyUrl", failures);
        AttestationConfigurationValidation.ValidateBoundedValue(attestation.Issuer, "SignIn.Attestation.Issuer", failures);
        AttestationConfigurationValidation.ValidateBoundedValue(attestation.Audience, "SignIn.Attestation.Audience", failures);
        AttestationConfigurationValidation.ValidateBoundedValue(attestation.ActiveKeyId, "SignIn.Attestation.ActiveKeyId", failures);

        if (attestation.Lifetime < TimeSpan.FromSeconds(10) || attestation.Lifetime > TimeSpan.FromSeconds(60))
        {
            failures.Add("SignIn.Attestation.Lifetime must be between 10 and 60 seconds.");
        }

        var duplicateKeyIds = attestation.SigningKeys
            .GroupBy(_ => _.KeyId, StringComparer.Ordinal)
            .Where(_ => _.Count() > 1)
            .Select(_ => _.Key)
            .ToArray();
        if (duplicateKeyIds.Length > 0)
        {
            failures.Add("SignIn.Attestation.SigningKeys must use unique, case-sensitive key identifiers.");
        }

        foreach (var key in attestation.SigningKeys)
        {
            AttestationConfigurationValidation.ValidateSigningKey(
                key.KeyId,
                key.PrivateKeyPem,
                "SignIn.Attestation.SigningKeys",
                failures);
        }

        if (attestation.SigningKeys.Count(_ => string.Equals(_.KeyId, attestation.ActiveKeyId, StringComparison.Ordinal)) != 1)
        {
            failures.Add("SignIn.Attestation.ActiveKeyId must identify exactly one configured signing key.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
