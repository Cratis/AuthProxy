// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware;

public class when_the_session_is_active : an_on_behalf_middleware
{
    OnBehalfContext _active;

    void Establish()
    {
        _active = new(Sessions.At(DateTimeOffset.UtcNow), Sessions.Represented(), "actor", Substitute.For<IOnBehalfAttestations>());
        _sessions.Resolve(_context).Returns(new OnBehalfResolution(OnBehalfResolutionStatus.Active, _active));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
    [Fact] void should_put_the_session_on_the_request() => (_context.TryGetOnBehalf(out var onBehalf) ? onBehalf : null).ShouldEqual(_active);
    [Fact] void should_make_the_represented_user_the_principal_the_request_acts_as() => _context.BuildClientPrincipal()!.UserId.ShouldEqual(Sessions.Subject);
    [Fact] void should_keep_the_actor_as_the_caller() => _context.BuildActorClientPrincipal()!.UserId.ShouldEqual(Sessions.ActorSubject);
}
