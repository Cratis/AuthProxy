// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Attestations;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Validates the on-behalf session configuration at startup.
/// </summary>
/// <remarks>
/// On-behalf sessions fail closed at run time — an unusable key or an unreachable application means no session is
/// ever issued — so a deployer would otherwise discover a mistake from support being unable to help anybody. Every
/// mistake that can be seen from the configuration alone is caught here instead.
/// </remarks>
sealed class OnBehalfConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    const string Section = "OnBehalf";

    /// <summary>
    /// Validates one AuthProxy configuration instance.
    /// </summary>
    /// <param name="name">The options instance name.</param>
    /// <param name="options">The configuration to validate.</param>
    /// <returns>All configuration failures, or a successful validation result.</returns>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var onBehalf = options.OnBehalf;
        if (onBehalf is null)
        {
            return ValidateOptionsResult.Success;
        }

        var failures = new List<string>();
        ValidateService(options, onBehalf, failures);
        ValidatePermittedServices(options, onBehalf, failures);
        ValidateIdentityVerification(options, onBehalf, failures);
        ValidateBounds(onBehalf, failures);

        if (!onBehalf.ActorAuthorization.HasRequirements
            || onBehalf.ActorAuthorization.RequiredClaims.Any(_ => string.IsNullOrWhiteSpace(_.Claim)))
        {
            failures.Add($"{Section}.ActorAuthorization.RequiredClaims must name at least one claim, so the deployment states who may act on behalf of others.");
        }

        ValidateAttestation(onBehalf.Attestation, failures);

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static void ValidateService(C.AuthProxy options, C.OnBehalf onBehalf, List<string> failures)
    {
        if (string.IsNullOrWhiteSpace(onBehalf.Service)
            || !options.Services.TryGetValue(onBehalf.Service, out var service)
            || service.Backend is null)
        {
            failures.Add($"{Section}.Service must name a configured service that declares a backend.");
            return;
        }

        AttestationConfigurationValidation.ValidateAbsoluteEndpoint(service.Backend.BaseUrl, $"Services.{onBehalf.Service}.Backend.BaseUrl", failures);
    }

    static void ValidatePermittedServices(C.AuthProxy options, C.OnBehalf onBehalf, List<string> failures)
    {
        if (onBehalf.Services.Count == 0)
        {
            return;
        }

        if (onBehalf.Services.Any(name => string.IsNullOrWhiteSpace(name) || !options.Services.Keys.Any(key => string.Equals(key, name.Trim(), StringComparison.OrdinalIgnoreCase))))
        {
            failures.Add($"{Section}.Services must only name configured services.");
        }

        if (!onBehalf.Permits(onBehalf.Service))
        {
            failures.Add($"{Section}.Services must include {Section}.Service, the service that grants the session.");
        }
    }

    static void ValidateIdentityVerification(C.AuthProxy options, C.OnBehalf onBehalf, List<string> failures)
    {
        // A Required service has to verify every identity, the represented user's included. One the session may not
        // reach could neither verify it nor be skipped, so the configuration is refused rather than either.
        var unreachable = options.Services
            .Where(_ => _.Value.ParticipatesInIdentityResolution
                && _.Value.IdentityVerification == C.IdentityVerificationMode.Required
                && !onBehalf.Permits(_.Key))
            .Select(_ => _.Key)
            .ToArray();

        if (unreachable.Length > 0)
        {
            failures.Add($"{Section}.Services must include every service whose identity verification is Required ({string.Join(", ", unreachable)}).");
        }
    }

    static void ValidateBounds(C.OnBehalf onBehalf, List<string> failures)
    {
        if (onBehalf.RecheckInterval < TimeSpan.FromSeconds(1) || onBehalf.RecheckInterval > TimeSpan.FromMinutes(5))
        {
            failures.Add($"{Section}.RecheckInterval must be between one second and five minutes.");
        }

        if (onBehalf.MaximumLifetime < TimeSpan.FromMinutes(1) || onBehalf.MaximumLifetime > TimeSpan.FromHours(24))
        {
            failures.Add($"{Section}.MaximumLifetime must be between one minute and twenty-four hours.");
        }

        if (onBehalf.Timeout < TimeSpan.FromSeconds(1) || onBehalf.Timeout > TimeSpan.FromSeconds(60))
        {
            failures.Add($"{Section}.Timeout must be between one and sixty seconds.");
        }
    }

    static void ValidateAttestation(C.OnBehalfAttestation? attestation, List<string> failures)
    {
        if (attestation is null)
        {
            failures.Add($"{Section}.Attestation is required: an on-behalf identity is never forwarded unsigned.");
            return;
        }

        AttestationConfigurationValidation.ValidateBoundedValue(attestation.Issuer, $"{Section}.Attestation.Issuer", failures);
        AttestationConfigurationValidation.ValidateBoundedValue(attestation.Audience, $"{Section}.Attestation.Audience", failures);
        AttestationConfigurationValidation.ValidateBoundedValue(attestation.ActiveKeyId, $"{Section}.Attestation.ActiveKeyId", failures);

        if (attestation.Lifetime < TimeSpan.FromSeconds(10) || attestation.Lifetime > TimeSpan.FromSeconds(60))
        {
            failures.Add($"{Section}.Attestation.Lifetime must be between 10 and 60 seconds.");
        }

        if (attestation.SigningKeys.GroupBy(_ => _.KeyId, StringComparer.Ordinal).Any(_ => _.Count() > 1))
        {
            failures.Add($"{Section}.Attestation.SigningKeys must use unique, case-sensitive key identifiers.");
        }

        foreach (var key in attestation.SigningKeys)
        {
            AttestationConfigurationValidation.ValidateSigningKey(key.KeyId, key.PrivateKeyPem, $"{Section}.Attestation.SigningKeys", failures);
        }

        if (attestation.SigningKeys.Count(_ => string.Equals(_.KeyId, attestation.ActiveKeyId, StringComparison.Ordinal)) != 1)
        {
            failures.Add($"{Section}.Attestation.ActiveKeyId must identify exactly one configured signing key.");
        }
    }
}
