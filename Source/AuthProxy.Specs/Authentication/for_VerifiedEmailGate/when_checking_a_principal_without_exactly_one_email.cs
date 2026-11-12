// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_VerifiedEmailGate;

public class when_checking_a_principal_without_exactly_one_email : given.a_principal_with_claims
{
    bool _noEmail;
    bool _blankEmail;
    bool _twoAddresses;
    bool _noPrincipal;

    void Because()
    {
        _noEmail = Satisfied(("email_verified", "true"));
        _blankEmail = Satisfied(("email", "  "), ("email_verified", "true"));
        _twoAddresses = Satisfied(("email", "a@example.com"), (ClaimTypes.Email, "b@example.com"), ("email_verified", "true"));
        _noPrincipal = VerifiedEmailGate.IsSatisfied(null, "email", "email_verified", includeMappedEmail: true);
    }

    [Fact] void should_refuse_a_missing_address() => _noEmail.ShouldBeFalse();
    [Fact] void should_refuse_a_blank_address() => _blankEmail.ShouldBeFalse();
    [Fact] void should_refuse_two_different_addresses() => _twoAddresses.ShouldBeFalse();
    [Fact] void should_refuse_no_principal() => _noPrincipal.ShouldBeFalse();
}
