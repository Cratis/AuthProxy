// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_VerifiedEmailGate;

public class when_checking_a_principal_that_does_not_prove_its_email : given.a_principal_with_claims
{
    bool _withoutVerification;
    bool _unverified;
    bool _numericVerification;
    bool _paddedVerification;
    bool _emptyVerification;
    bool _conflictingVerifications;
    bool _repeatedWithOneFalse;

    void Because()
    {
        _withoutVerification = Satisfied(("email", "a@example.com"));
        _unverified = Satisfied(("email", "a@example.com"), ("email_verified", "false"));
        _numericVerification = Satisfied(("email", "a@example.com"), ("email_verified", "1"));
        _paddedVerification = Satisfied(("email", "a@example.com"), ("email_verified", "true "));
        _emptyVerification = Satisfied(("email", "a@example.com"), ("email_verified", string.Empty));
        _conflictingVerifications = Satisfied(("email", "a@example.com"), ("email_verified", "true"), ("email_verified", "false"));
        _repeatedWithOneFalse = Satisfied(("email", "a@example.com"), ("email_verified", "true"), ("email_verified", "true"), ("email_verified", "false"));
    }

    [Fact] void should_refuse_a_missing_verification() => _withoutVerification.ShouldBeFalse();
    [Fact] void should_refuse_false() => _unverified.ShouldBeFalse();
    [Fact] void should_refuse_a_number() => _numericVerification.ShouldBeFalse();
    [Fact] void should_refuse_padded_text() => _paddedVerification.ShouldBeFalse();
    [Fact] void should_refuse_an_empty_value() => _emptyVerification.ShouldBeFalse();
    [Fact] void should_refuse_conflicting_verifications() => _conflictingVerifications.ShouldBeFalse();
    [Fact] void should_refuse_repeated_verifications_when_one_is_false() => _repeatedWithOneFalse.ShouldBeFalse();
}
