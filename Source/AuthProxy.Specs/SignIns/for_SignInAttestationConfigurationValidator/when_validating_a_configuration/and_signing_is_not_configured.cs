// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// Every deployment that has not opted in must start unaffected — including the ones whose notify URL would
/// never satisfy the rules that only apply to a signing deployment.
/// </summary>
public class and_signing_is_not_configured : a_sign_in_attestation_configuration
{
    ValidateOptionsResult _withoutTheSection;
    ValidateOptionsResult _withoutSignIn;

    void Because()
    {
        _withoutTheSection = Validate(new C.AuthProxy { SignIn = new C.SignIn { NotifyUrl = "not-a-url" } });
        _withoutSignIn = Validate(new C.AuthProxy());
    }

    [Fact] void should_accept_an_unsigned_notification_configuration() => _withoutTheSection.Succeeded.ShouldBeTrue();
    [Fact] void should_accept_a_configuration_without_sign_ins_at_all() => _withoutSignIn.Succeeded.ShouldBeTrue();
}
