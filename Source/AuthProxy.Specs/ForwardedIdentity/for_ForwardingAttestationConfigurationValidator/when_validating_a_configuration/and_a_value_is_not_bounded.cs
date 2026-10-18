// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// The issuer and every audience are compared exactly by the verifier, so a blank, padded or control-character value
/// is rejected rather than signed into an assertion nobody can match.
/// </summary>
public class and_a_value_is_not_bounded : a_forwarding_attestation_configuration
{
    ValidateOptionsResult _blankIssuer;
    ValidateOptionsResult _paddedIssuer;
    ValidateOptionsResult _blankServiceAudience;

    void Because()
    {
        _blankIssuer = Validate(Configuration(issuer: " ", signingKeys: P256Key("current")));
        _paddedIssuer = Validate(Configuration(issuer: " https://auth.example.com", signingKeys: P256Key("current")));

        var configuration = Configuration(signingKeys: P256Key("current"));
        configuration.Services["reports"] = new C.Service { ForwardingAudience = "" };
        _blankServiceAudience = Validate(configuration);
    }

    [Fact] void should_reject_a_blank_issuer() => _blankIssuer.Succeeded.ShouldBeFalse();
    [Fact] void should_reject_a_padded_issuer() => _paddedIssuer.Succeeded.ShouldBeFalse();
    [Fact] void should_reject_a_blank_service_audience() => _blankServiceAudience.Succeeded.ShouldBeFalse();
}
