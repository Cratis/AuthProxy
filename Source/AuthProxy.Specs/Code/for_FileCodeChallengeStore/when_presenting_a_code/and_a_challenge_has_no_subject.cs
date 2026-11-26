// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Code.for_FileCodeChallengeStore.when_presenting_a_code;

public class and_a_challenge_has_no_subject : given.a_store_with_a_challenge
{
    CodeVerification _result = null!;

    async Task Because()
    {
        var salt = CodeHash.NewSalt();
        await _store.Create(new CodeChallenge("no-subject", Scheme, "x@example.com", string.Empty, salt, CodeHash.Compute(salt, TheCode), _time.GetUtcNow().AddMinutes(10), 0, false));
        _result = await _store.Verify(Scheme, "no-subject", TheCode, MaxAttempts);
    }

    [Fact] void should_treat_even_the_matching_code_as_wrong() => _result.Outcome.ShouldEqual(CodeVerificationOutcome.Wrong);
}
