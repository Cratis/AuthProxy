// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// A rotation that leaves the active identifier pointing at nothing signs nothing, which at run time means
/// every sign-in stops being recorded. That has to be a startup failure, not a silent one.
/// </summary>
public class and_the_active_key_identifier_matches_no_key : a_sign_in_attestation_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(Configuration(activeKeyId: "retired", signingKeys: PrivateKey("current")));

    [Fact] void should_reject_the_configuration() => _result.Succeeded.ShouldBeFalse();
}
