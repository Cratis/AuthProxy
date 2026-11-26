// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_CodeProviderConfigurationValidator;

public class when_validating : Specification
{
    static readonly string _pem = CreatePem();

    ValidateOptionsResult _complete = null!;
    ValidateOptionsResult _withoutAttestation = null!;
    ValidateOptionsResult _withoutSettings = null!;
    ValidateOptionsResult _badRequestUrl = null!;
    ValidateOptionsResult _badLimits = null!;
    ValidateOptionsResult _canonicalWithoutIssuer = null!;
    ValidateOptionsResult _settingsOnAnotherType = null!;

    void Because()
    {
        var validator = new CodeProviderConfigurationValidator();
        _complete = validator.Validate(null, Configure());
        _withoutAttestation = validator.Validate(null, Configure(settings: Settings(withAttestation: false)));
        _withoutSettings = validator.Validate(null, Configure(withSettings: false));
        _badRequestUrl = validator.Validate(null, Configure(settings: Settings(requestUrl: "not a url")));
        _badLimits = validator.Validate(null, Configure(settings: Settings(codeLength: 2, maxAttempts: 0, lifetime: TimeSpan.FromDays(1))));
        _canonicalWithoutIssuer = validator.Validate(null, Configure(settings: Settings(issuer: string.Empty), canonical: true));
        _settingsOnAnotherType = validator.Validate(null, Configure(C.OidcProviderType.Custom));
    }

    static string CreatePem()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        return rsa.ExportPkcs8PrivateKeyPem();
    }

    static C.CodeSignIn Settings(string requestUrl = "https://app.example/_code", string issuer = "https://app.example/.cratis/code", int codeLength = 6, int maxAttempts = 5, TimeSpan? lifetime = null, bool withAttestation = true) =>
        new()
        {
            RequestUrl = requestUrl,
            Attestation = withAttestation ? new C.SignInAttestation { Issuer = "authproxy", Audience = "app", ActiveKeyId = "k1", SigningKeys = [new C.SignInAttestationSigningKey { KeyId = "k1", PrivateKeyPem = _pem }] } : null,
            Issuer = issuer,
            CodeLength = codeLength,
            MaxAttempts = maxAttempts,
            Lifetime = lifetime ?? TimeSpan.FromMinutes(10),
        };

    static C.AuthProxy Configure(
        C.OidcProviderType type = C.OidcProviderType.Code,
        C.CodeSignIn? settings = null,
        bool withSettings = true,
        bool canonical = false)
    {
        var provider = new C.OidcProvider
        {
            Name = "Code",
            Type = type,
            Code = withSettings ? settings ?? Settings() : null,
            CanonicalIdentity = canonical ? new C.CanonicalIdentity { ProviderKey = "code", SubjectClaimType = "sub" } : null,
        };
        return new C.AuthProxy { Authentication = new C.Authentication { OidcProviders = [provider] } };
    }

    [Fact] void should_accept_a_complete_provider() => _complete.Succeeded.ShouldBeTrue();
    [Fact] void should_require_the_attestation() => _withoutAttestation.Failed.ShouldBeTrue();
    [Fact] void should_require_the_settings() => _withoutSettings.Failed.ShouldBeTrue();
    [Fact] void should_require_an_absolute_request_url() => _badRequestUrl.Failed.ShouldBeTrue();
    [Fact] void should_bound_length_attempts_and_lifetime() => _badLimits.Failures!.Count().ShouldEqual(3);
    [Fact] void should_require_an_issuer_for_a_canonical_identity() => _canonicalWithoutIssuer.Failed.ShouldBeTrue();
    [Fact] void should_refuse_code_settings_on_another_provider_type() => _settingsOnAnotherType.Failed.ShouldBeTrue();
}
