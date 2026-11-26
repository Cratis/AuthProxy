// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Code.for_FileCodeChallengeStore.when_presenting_a_code;

public class and_the_code_has_expired : given.a_store_with_a_challenge
{
    CodeVerification _result = null!;

    async Task Because()
    {
        _time.Advance(TimeSpan.FromMinutes(11));
        _result = await _store.Verify(Scheme, _challenge.Id, TheCode, MaxAttempts);
    }

    [Fact] void should_refuse() => _result.Outcome.ShouldEqual(CodeVerificationOutcome.Refused);
}
