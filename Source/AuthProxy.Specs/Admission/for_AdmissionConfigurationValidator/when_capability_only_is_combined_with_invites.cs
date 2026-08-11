// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionConfigurationValidator;

/// <summary>
/// Two capability mechanisms in one deployment is a misconfiguration, and it is refused rather than
/// silently ordered.
/// <para>
/// An invitation is already a capability: it has its own issuance, its own protected browser state and its
/// own refusals — and in a closed deployment it would be reached only through a door admission has already
/// shut. Whichever precedence shipped would immediately become the contract, so refusing the combination is
/// what keeps the door open to unifying them later, with an invitation becoming one kind of admission
/// capability rather than a second mechanism beside it.
/// </para>
/// </summary>
public class when_capability_only_is_combined_with_invites : given.an_admission_configuration_validator
{
    void Establish() => _config.Invite = new C.Invite { PublicKeyPem = "-----BEGIN PUBLIC KEY-----" };

    void Because() => _result = _validator.Validate(null, _config);

    [Fact] void should_refuse_the_configuration() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_mode() => Failures().ShouldContain($"{C.Admission.SectionKey}:{nameof(C.Admission.Mode)}");
    [Fact] void should_name_the_invite_section() => Failures().ShouldContain($"{C.AuthProxy.SectionKey}:Invite");
    [Fact] void should_say_the_two_may_yet_be_unified() => Failures().ShouldContain("unifying them later");
}
