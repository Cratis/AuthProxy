// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_VerifiedEmailGate;

public class when_checking_a_principal_with_one_verified_email : given.a_principal_with_claims
{
    bool _plain;
    bool _capitalized;
    bool _sameAddressInBothClaimTypes;

    void Because()
    {
        _plain = Satisfied(("email", "a@example.com"), ("email_verified", "true"));
        _capitalized = Satisfied(("email", "a@example.com"), ("email_verified", "True"));
        _sameAddressInBothClaimTypes = Satisfied(("email", "a@example.com"), (ClaimTypes.Email, "A@example.com"), ("email_verified", "true"));
    }

    [Fact] void should_be_satisfied() => _plain.ShouldBeTrue();
    [Fact] void should_accept_the_text_a_json_boolean_produces() => _capitalized.ShouldBeTrue();
    [Fact] void should_treat_the_same_address_under_two_claim_types_as_one() => _sameAddressInBothClaimTypes.ShouldBeTrue();
}
