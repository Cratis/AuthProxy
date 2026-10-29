// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfConfigurationValidator.when_validating;

/// <summary>
/// A service that must verify every identity can neither be asked about the represented user, which the session may
/// not reach it with, nor be skipped. The configuration is refused rather than either.
/// </summary>
public class and_a_required_identity_verifier_is_not_permitted : Specification
{
    ValidateOptionsResult _result;

    void Because()
    {
        var configuration = new OnBehalfConfiguration().Value;
        configuration.Services["lobby"] = new()
        {
            Backend = new() { BaseUrl = "https://lobby.internal" },
            IdentityVerification = C.IdentityVerificationMode.Required,
        };
        _result = new OnBehalfConfigurationValidator().Validate(null, configuration);
    }

    [Fact] void should_fail() => _result.FailureMessage.ShouldContain("every service whose identity verification is Required (lobby)");
}
