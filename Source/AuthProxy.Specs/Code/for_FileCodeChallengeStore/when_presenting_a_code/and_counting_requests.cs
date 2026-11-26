// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Code.for_FileCodeChallengeStore.when_presenting_a_code;

public class and_counting_requests : given.a_store_with_a_challenge
{
    bool[] _within = [];
    bool _afterTheWindow;
    bool _otherKey;

    async Task Because()
    {
        var window = TimeSpan.FromMinutes(10);
        _within = [await _store.TryCount("k", 2, window), await _store.TryCount("k", 2, window), await _store.TryCount("k", 2, window)];
        _otherKey = await _store.TryCount("other", 2, window);
        _time.Advance(TimeSpan.FromMinutes(11));
        _afterTheWindow = await _store.TryCount("k", 2, window);
    }

    [Fact] void should_allow_requests_up_to_the_limit() => (_within[0] && _within[1]).ShouldBeTrue();
    [Fact] void should_refuse_the_request_over_the_limit() => _within[2].ShouldBeFalse();
    [Fact] void should_count_keys_separately() => _otherKey.ShouldBeTrue();
    [Fact] void should_allow_again_after_the_window() => _afterTheWindow.ShouldBeTrue();
}
