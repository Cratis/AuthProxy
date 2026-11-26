// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Attestations;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Validates providers that sign people in with a code AuthProxy issues, so a deployment that cannot work fails at startup.
/// </summary>
public sealed class CodeProviderConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        List<string> failures = [];
        foreach (var provider in options.Authentication.OidcProviders)
        {
            var path = $"Provider '{provider.Name}'";
            if (provider.Type != C.OidcProviderType.Code)
            {
                if (provider.Code is not null)
                {
                    failures.Add($"{path} sets Code settings but is not of type Code.");
                }

                continue;
            }

            Validate(path, provider, failures);
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static void Validate(string path, C.OidcProvider provider, List<string> failures)
    {
        var code = provider.Code;
        if (code is null)
        {
            failures.Add($"{path} is of type Code and needs Code settings.");
            return;
        }

        if (!Uri.TryCreate(code.RequestUrl, UriKind.Absolute, out var url) || url.Scheme is not ("https" or "http"))
        {
            failures.Add($"{path}: Code:RequestUrl must be an absolute HTTP or HTTPS address.");
        }

        ValidateAttestation(path, code.Attestation, failures);

        if (code.CodeLength is < 4 or > 10)
        {
            failures.Add($"{path}: Code:CodeLength must be between 4 and 10.");
        }

        if (code.MaxAttempts is < 1 or > 10)
        {
            failures.Add($"{path}: Code:MaxAttempts must be between 1 and 10.");
        }

        if (code.Lifetime < TimeSpan.FromMinutes(1) || code.Lifetime > TimeSpan.FromHours(1))
        {
            failures.Add($"{path}: Code:Lifetime must be between one minute and one hour.");
        }

        if (code.Throttle.PerAddress < 1 || code.Throttle.PerClient < 1 || code.Throttle.Window <= TimeSpan.Zero)
        {
            failures.Add($"{path}: Code:Throttle limits must be at least 1 and its window positive.");
        }

        if (provider.CanonicalIdentity is not null && !CanonicalIssuer.TryNormalize(code.Issuer, out _))
        {
            failures.Add($"{path}: a code provider with a canonical identity needs Code:Issuer, an absolute HTTPS address that never changes.");
        }
    }

    static void ValidateAttestation(string path, C.SignInAttestation? attestation, List<string> failures)
    {
        if (attestation is null)
        {
            failures.Add($"{path}: a code provider needs Code:Attestation, so the application can tell that AuthProxy is asking it to send a code.");
            return;
        }

        var section = $"{path}: Code:Attestation";
        AttestationConfigurationValidation.ValidateBoundedValue(attestation.Issuer, $"{section}:Issuer", failures);
        AttestationConfigurationValidation.ValidateBoundedValue(attestation.Audience, $"{section}:Audience", failures);
        AttestationConfigurationValidation.ValidateBoundedValue(attestation.ActiveKeyId, $"{section}:ActiveKeyId", failures);

        if (attestation.Lifetime < TimeSpan.FromSeconds(10) || attestation.Lifetime > TimeSpan.FromSeconds(60))
        {
            failures.Add($"{section}:Lifetime must be between 10 and 60 seconds.");
        }

        if (attestation.SigningKeys.GroupBy(_ => _.KeyId, StringComparer.Ordinal).Any(_ => _.Count() > 1))
        {
            failures.Add($"{section}:SigningKeys must use unique, case-sensitive key identifiers.");
        }

        foreach (var key in attestation.SigningKeys)
        {
            AttestationConfigurationValidation.ValidateSigningKey(key.KeyId, key.PrivateKeyPem, $"{section}:SigningKeys", failures);
        }

        if (attestation.SigningKeys.Count(_ => string.Equals(_.KeyId, attestation.ActiveKeyId, StringComparison.Ordinal)) != 1)
        {
            failures.Add($"{section}:ActiveKeyId must identify exactly one configured signing key.");
        }
    }
}
