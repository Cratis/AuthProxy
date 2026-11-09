// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics;
using Cratis.AuthProxy.BearerRoutes.for_BearerTokenIntrospector.given;
using Cratis.AuthProxy.BearerRoutes.Introspection;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerTokenIntrospector;

/// <summary>
/// An active answer is reused for at most the cache window and never past the token's own expiry; an inactive or
/// failed answer is never reused, so a re-activated token or a recovered endpoint is honored at once. Concurrent
/// requests share one call, one caller giving up does not fail the others, and a silent endpoint is abandoned at
/// the configured timeout.
/// </summary>
public class when_tokens_are_presented_repeatedly : Specification
{
    IntrospectionVerdict _afterCachedActive;
    int _callsAfterCachedActive;
    IntrospectionVerdict _afterWindow;
    int _callsAfterWindow;
    IntrospectionVerdict _otherToken;
    int _callsAfterOtherToken;
    IntrospectionVerdict _inactiveThenActive;
    int _callsForInactive;
    IntrospectionVerdict _expiringToken;
    int _callsForExpiringToken;
    IntrospectionVerdict _withoutCache;
    int _callsWithoutCache;
    IntrospectionVerdict[] _concurrent;
    int _callsForConcurrent;
    IntrospectionVerdict[] _afterAbort;
    bool _abortedCallerCanceled;
    IntrospectionVerdict _timedOut;
    TimeSpan _timedOutAfter;
    IntrospectionVerdict _afterFailureThenRecovery;

    async Task Because()
    {
        var active = new ScriptedIntrospection(_ => Task.FromResult(ScriptedIntrospection.Json("""{"active":true}""")));
        await active.Introspect();
        _afterCachedActive = await active.Introspect();
        _callsAfterCachedActive = active.Calls;
        _otherToken = await active.Introspect(ScriptedIntrospection.Token + "x");
        _callsAfterOtherToken = active.Calls;
        active.Time.Advance(TimeSpan.FromSeconds(31));
        _afterWindow = await active.Introspect();
        _callsAfterWindow = active.Calls;

        var answer = """{"active":false}""";
        var flipping = new ScriptedIntrospection(_ => Task.FromResult(ScriptedIntrospection.Json(answer)));
        await flipping.Introspect();
        await flipping.Introspect();
        _callsForInactive = flipping.Calls;
        answer = """{"active":true}""";
        _inactiveThenActive = await flipping.Introspect();

        var expiring = new ScriptedIntrospection(_ => Task.FromResult(ScriptedIntrospection.Json("""{"active":true}""")));
        var exp = expiring.Time.GetUtcNow().AddSeconds(5).ToUnixTimeSeconds();
        await expiring.Introspect(expires: exp);
        expiring.Time.Advance(TimeSpan.FromSeconds(6));
        _expiringToken = await expiring.Introspect(expires: exp);
        _callsForExpiringToken = expiring.Calls;

        var uncached = new ScriptedIntrospection(_ => Task.FromResult(ScriptedIntrospection.Json("""{"active":true}""")), cacheDuration: TimeSpan.Zero);
        await uncached.Introspect();
        _withoutCache = await uncached.Introspect();
        _callsWithoutCache = uncached.Calls;

        var gate = new TaskCompletionSource();
        var shared = new ScriptedIntrospection(async _ =>
        {
            await gate.Task;
            return ScriptedIntrospection.Json("""{"active":true}""");
        });
        using var abort = new CancellationTokenSource();
        var first = shared.Introspect(cancellationToken: abort.Token);
        var others = Enumerable.Range(0, 10).Select(_ => shared.Introspect()).ToArray();
        await abort.CancelAsync();
        try
        {
            await first;
        }
        catch (OperationCanceledException)
        {
            _abortedCallerCanceled = true;
        }

        gate.SetResult();
        _concurrent = await Task.WhenAll(others);
        _callsForConcurrent = shared.Calls;
        _afterAbort = [await shared.Introspect()];

        var silent = new ScriptedIntrospection(_ => new TaskCompletionSource<HttpResponseMessage>().Task, timeout: TimeSpan.FromMilliseconds(200));
        var stopwatch = Stopwatch.StartNew();
        _timedOut = await silent.Introspect();
        _timedOutAfter = stopwatch.Elapsed;

        var fail = true;
        var recovering = new ScriptedIntrospection(_ => fail
            ? throw new HttpRequestException("down")
            : Task.FromResult(ScriptedIntrospection.Json("""{"active":true}""")));
        await recovering.Introspect();
        fail = false;
        _afterFailureThenRecovery = await recovering.Introspect();
    }

    [Fact] void should_reuse_an_active_answer_within_the_window() => _afterCachedActive.ShouldEqual(IntrospectionVerdict.Active);
    [Fact] void should_not_call_the_endpoint_again_within_the_window() => _callsAfterCachedActive.ShouldEqual(1);
    [Fact] void should_not_serve_another_token_from_the_entry() => _callsAfterOtherToken.ShouldEqual(2);
    [Fact] void should_accept_the_other_token_on_its_own_answer() => _otherToken.ShouldEqual(IntrospectionVerdict.Active);
    [Fact] void should_ask_again_once_the_window_has_passed() => _callsAfterWindow.ShouldEqual(3);
    [Fact] void should_still_be_active_after_asking_again() => _afterWindow.ShouldEqual(IntrospectionVerdict.Active);
    [Fact] void should_not_cache_an_inactive_answer() => _callsForInactive.ShouldEqual(2);
    [Fact] void should_honor_a_re_activated_token_at_once() => _inactiveThenActive.ShouldEqual(IntrospectionVerdict.Active);
    [Fact] void should_not_serve_an_expired_token_from_the_cache() => _callsForExpiringToken.ShouldEqual(2);
    [Fact] void should_not_cache_when_the_window_is_zero() => _callsWithoutCache.ShouldEqual(2);
    [Fact] void should_answer_every_call_without_cache() => _withoutCache.ShouldEqual(IntrospectionVerdict.Active);
    [Fact] void should_share_one_call_between_concurrent_requests() => _callsForConcurrent.ShouldEqual(1);
    [Fact] void should_answer_every_concurrent_request() => _concurrent.ShouldEachConformTo(_ => _ == IntrospectionVerdict.Active);
    [Fact] void should_let_a_caller_give_up_on_its_own() => _abortedCallerCanceled.ShouldBeTrue();
    [Fact] void should_not_leave_a_flight_stuck() => _afterAbort[0].ShouldEqual(IntrospectionVerdict.Active);
    [Fact] void should_be_unavailable_when_the_endpoint_never_answers() => _timedOut.ShouldEqual(IntrospectionVerdict.Unavailable);
    [Fact] void should_give_up_at_the_configured_timeout() => _timedOutAfter.ShouldBeLessThan(TimeSpan.FromSeconds(2));
    [Fact] void should_recover_when_the_endpoint_does() => _afterFailureThenRecovery.ShouldEqual(IntrospectionVerdict.Active);
}
