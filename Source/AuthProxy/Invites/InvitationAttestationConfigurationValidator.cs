// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Attestations;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Validates the cryptographic and endpoint configuration for signed invitation attestations.
/// </summary>
sealed class InvitationAttestationConfigurationValidator : IValidateOptions<C.AuthProxy>
{
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
        AttestationConfigurationValidation.ValidateAbsoluteEndpoint(invite!.StageUrl, "Invite.StageUrl", failures);
        AttestationConfigurationValidation.ValidateAbsoluteEndpoint(invite.ExchangeUrl, "Invite.ExchangeUrl", failures);
        AttestationConfigurationValidation.ValidateBoundedValue(attestation.Issuer, "Invite.Attestation.Issuer", failures);
        AttestationConfigurationValidation.ValidateBoundedValue(attestation.Audience, "Invite.Attestation.Audience", failures);
        AttestationConfigurationValidation.ValidateBoundedValue(attestation.ActiveKeyId, "Invite.Attestation.ActiveKeyId", failures);

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
            AttestationConfigurationValidation.ValidateSigningKey(
                key.KeyId,
                key.PrivateKeyPem,
                "Invite.Attestation.SigningKeys",
                failures);
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
}
