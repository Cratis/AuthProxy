// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Code.for_FileCodeChallengeStore.when_presenting_a_code;

public class and_the_code_is_wrong_repeatedly : given.a_store_with_a_challenge
{
    CodeVerification _first = null!;
    CodeVerification _second = null!;
    CodeVerification _third = null!;
    CodeVerification _rightAfterwards = null!;

    async Task Because()
    {
        _first = await _store.Verify(Scheme, _challenge.Id, "000000", MaxAttempts);
        _second = await _store.Verify(Scheme, _challenge.Id, "000000", MaxAttempts);
        _third = await _store.Verify(Scheme, _challenge.Id, "000000", MaxAttempts);
        _rightAfterwards = await _store.Verify(Scheme, _challenge.Id, TheCode, MaxAttempts);
    }

    [Fact] void should_allow_another_try_while_attempts_remain() => _first.Outcome.ShouldEqual(CodeVerificationOutcome.Wrong);
    [Fact] void should_still_allow_a_try_on_the_second_wrong_code() => _second.Outcome.ShouldEqual(CodeVerificationOutcome.Wrong);
    [Fact] void should_destroy_the_challenge_at_the_limit() => _third.Outcome.ShouldEqual(CodeVerificationOutcome.Refused);
    [Fact] void should_refuse_the_right_code_afterwards() => _rightAfterwards.Outcome.ShouldEqual(CodeVerificationOutcome.Refused);
}
