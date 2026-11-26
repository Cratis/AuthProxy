// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Code.for_FileCodeChallengeStore.when_presenting_a_code;

public class and_the_code_is_right : given.a_store_with_a_challenge
{
    CodeVerification _first = null!;
    CodeVerification _second = null!;

    async Task Because()
    {
        _first = await _store.Verify(Scheme, _challenge.Id, TheCode, MaxAttempts);
        _second = await _store.Verify(Scheme, _challenge.Id, TheCode, MaxAttempts);
    }

    [Fact] void should_verify() => _first.Outcome.ShouldEqual(CodeVerificationOutcome.Verified);
    [Fact] void should_name_the_subject() => _first.Challenge!.Subject.ShouldEqual("user-1");
    [Fact] void should_refuse_the_same_code_again() => _second.Outcome.ShouldEqual(CodeVerificationOutcome.Refused);
}
