// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_resolving;

/// <summary>
/// Every request of a page load can find the grant answer stale at once. They share one call to the application
/// rather than each making their own.
/// </summary>
public class and_several_requests_need_a_recheck_at_once : a_session_coordinator
{
    TaskCompletionSource<OnBehalfGrant> _answer;
    OnBehalfResolution[] _results;

    void Establish()
    {
        Carry(Sessions.At(_start));
        _answer = new(TaskCreationOptions.RunContinuationsAsynchronously);
        _grants.Check(Arg.Any<OnBehalfSession>(), Arg.Any<ClientPrincipal>(), Arg.Any<CancellationToken>()).Returns(_answer.Task);
    }

    async Task Because()
    {
        var requests = Enumerable.Range(0, 5).Select(_ => _sessions.Resolve(Copy())).ToArray();
        _answer.SetResult(OnBehalfGrant.Live(_start.AddHours(2), Sessions.Represented()));
        _results = await Task.WhenAll(requests);
    }

    DefaultHttpContext Copy()
    {
        var copy = new DefaultHttpContext { User = Sessions.ActorPrincipal() };
        copy.Request.Headers.Cookie = _context.Request.Headers.Cookie;
        return copy;
    }

    [Fact] void should_ask_the_application_once() => _grants.Received(1).Check(Arg.Any<OnBehalfSession>(), Arg.Any<ClientPrincipal>(), Arg.Any<CancellationToken>());
    [Fact] void should_make_every_request_active() => _results.All(_ => _.Status == OnBehalfResolutionStatus.Active).ShouldBeTrue();
}
