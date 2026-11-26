// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Code.for_FileCodeChallengeStore.when_presenting_a_code;

public class and_the_same_code_is_presented_at_once : given.a_store_with_a_challenge
{
    CodeVerification[] _results = [];

    async Task Because() =>
        _results = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => Task.Run(() => _store.Verify(Scheme, _challenge.Id, TheCode, MaxAttempts))));

    [Fact] void should_verify_exactly_once() => _results.Count(_ => _.Outcome == CodeVerificationOutcome.Verified).ShouldEqual(1);
}
