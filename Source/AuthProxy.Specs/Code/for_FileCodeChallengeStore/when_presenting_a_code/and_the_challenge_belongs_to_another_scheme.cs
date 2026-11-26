// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Code.for_FileCodeChallengeStore.when_presenting_a_code;

public class and_the_challenge_belongs_to_another_scheme : given.a_store_with_a_challenge
{
    CodeVerification _otherScheme = null!;
    CodeVerification _pathLikeIdentifier = null!;

    async Task Because()
    {
        _otherScheme = await _store.Verify("other", _challenge.Id, TheCode, MaxAttempts);
        _pathLikeIdentifier = await _store.Verify(Scheme, "../challenge-1", TheCode, MaxAttempts);
    }

    [Fact] void should_refuse_another_scheme() => _otherScheme.Outcome.ShouldEqual(CodeVerificationOutcome.Refused);
    [Fact] void should_refuse_an_identifier_that_is_a_path() => _pathLikeIdentifier.Outcome.ShouldEqual(CodeVerificationOutcome.Refused);
}
