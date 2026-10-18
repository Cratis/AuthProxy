// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.Attestations;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>
/// Validates the signed forwarding configuration at startup.
/// </summary>
/// <remarks>
/// A deployment that signs refuses to forward what it cannot sign, so an unusable key would turn every request into
/// a <c language="text">502</c>. Every shape that would fail at run time — a key that is not an EC P-256 private
/// key, an active key that is not configured, a lifetime outside the bounds, or a tenant-selection endpoint with no
/// audience to sign for — fails startup instead.
/// </remarks>
sealed class ForwardingAttestationConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    const string Section = nameof(C.AuthProxy.ForwardingAttestation);
    const string P256Oid = "1.2.840.10045.3.1.7";

    static readonly string[] _p256Names = ["nistP256", "ECDSA_P256", "prime256v1", "secp256r1"];

    /// <summary>
    /// Validates one AuthProxy configuration instance.
    /// </summary>
    /// <param name="name">The options instance name.</param>
    /// <param name="options">The configuration to validate.</param>
    /// <returns>All configuration failures, or a successful validation result.</returns>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var attestation = options.ForwardingAttestation;
        if (attestation is null)
        {
            return ValidateOptionsResult.Success;
        }

        var failures = new List<string>();
        AttestationConfigurationValidation.ValidateBoundedValue(attestation.Issuer, $"{Section}.Issuer", failures);
        AttestationConfigurationValidation.ValidateBoundedValue(attestation.ActiveKeyId, $"{Section}.ActiveKeyId", failures);

        if (attestation.Lifetime < C.ForwardingAttestation.MinimumLifetime || attestation.Lifetime > C.ForwardingAttestation.MaximumLifetime)
        {
            failures.Add($"{Section}.Lifetime must be between {C.ForwardingAttestation.MinimumLifetime.TotalSeconds} and {C.ForwardingAttestation.MaximumLifetime.TotalSeconds} seconds.");
        }

        ValidateSigningKeys(attestation, failures);
        ValidateAudiences(options, failures);

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    static void ValidateSigningKeys(C.ForwardingAttestation attestation, List<string> failures)
    {
        const string path = $"{Section}.SigningKeys";
        if (attestation.SigningKeys.GroupBy(_ => _.KeyId, StringComparer.Ordinal).Any(_ => _.Count() > 1))
        {
            failures.Add($"{path} must use unique, case-sensitive key identifiers.");
        }

        foreach (var key in attestation.SigningKeys)
        {
            AttestationConfigurationValidation.ValidateKeyId(key.KeyId, path, failures);
            ValidatePrivateKey(key.PrivateKeyPem, path, failures);
        }

        if (attestation.SigningKeys.Count(_ => string.Equals(_.KeyId, attestation.ActiveKeyId, StringComparison.Ordinal)) != 1)
        {
            failures.Add($"{Section}.ActiveKeyId must identify exactly one configured signing key.");
        }
    }

    static void ValidatePrivateKey(string privateKeyPem, string path, List<string> failures)
    {
        if (string.IsNullOrWhiteSpace(privateKeyPem))
        {
            failures.Add($"{path}.PrivateKeyPem is required.");
            return;
        }

        try
        {
            using var key = ECDsa.Create();
            key.ImportFromPem(privateKeyPem);
            var parameters = key.ExportParameters(includePrivateParameters: true);
            if (parameters.D is null || key.KeySize != 256 || !IsP256(parameters.Curve))
            {
                failures.Add($"{path}.PrivateKeyPem must contain an EC P-256 private key.");
            }
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            failures.Add($"{path}.PrivateKeyPem must contain a valid EC P-256 private key.");
        }
    }

    static bool IsP256(ECCurve curve) =>
        curve.IsNamed
        && (string.Equals(curve.Oid.Value, P256Oid, StringComparison.Ordinal)
            || _p256Names.Contains(curve.Oid.FriendlyName, StringComparer.OrdinalIgnoreCase));

    static void ValidateAudiences(C.AuthProxy options, List<string> failures)
    {
        foreach (var (serviceName, service) in options.Services)
        {
            if (service.ForwardingAudience is not null)
            {
                AttestationConfigurationValidation.ValidateBoundedValue(service.ForwardingAudience, $"Services.{serviceName}.ForwardingAudience", failures);
            }
        }

        if (!TenantSelectionMiddleware.TryGetSelectionOptions(options, out var selection))
        {
            return;
        }

        if (selection.ForwardingAudience is not null)
        {
            AttestationConfigurationValidation.ValidateBoundedValue(selection.ForwardingAudience, "TenantResolutions.Selection.Options.ForwardingAudience", failures);
        }

        if (ForwardingAudiences.ForTenantSelection(options, selection, out var ambiguous) is null)
        {
            failures.Add(ambiguous
                ? "The tenant selection endpoint is served by several services with different forwarding audiences. Set the selection strategy's Options.ForwardingAudience."
                : "The tenant selection endpoint is not served by any configured service backend. Set the selection strategy's Options.ForwardingAudience.");
        }
    }
}
