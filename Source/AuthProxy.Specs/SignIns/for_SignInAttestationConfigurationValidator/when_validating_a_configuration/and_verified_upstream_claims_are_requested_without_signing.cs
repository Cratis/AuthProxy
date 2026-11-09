// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// Verified claims are only ever sent inside a signed body, so asking for them without a signing section is a
/// misconfiguration that must stop the host rather than silently send claims unsigned or never.
/// </summary>
public class and_verified_upstream_claims_are_requested_without_signing : a_sign_in_attestation_configuration
{
    ValidateOptionsResult _unsigned;
    ValidateOptionsResult _signed;

    void Because()
    {
        _unsigned = Validate(new C.AuthProxy { SignIn = new C.SignIn { NotifyUrl = NotifyUrl, IncludeVerifiedUpstreamClaims = true } });
        var configuration = Configuration(signingKeys: PrivateKey("current"));
        configuration.SignIn.IncludeVerifiedUpstreamClaims = true;
        _signed = Validate(configuration);
    }

    [Fact] void should_reject_claims_without_a_signed_envelope() => _unsigned.Succeeded.ShouldBeFalse();
    [Fact] void should_accept_claims_with_a_signed_envelope() => _signed.Succeeded.ShouldBeTrue();
}
