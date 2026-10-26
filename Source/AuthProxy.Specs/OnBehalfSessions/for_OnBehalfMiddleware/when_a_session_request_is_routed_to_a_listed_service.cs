// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware;

/// <summary>
/// A deployment can let a session reach more than the granting service by listing them, and a request to one of them
/// goes through, matched case-insensitively like every other service name.
/// </summary>
public class when_a_session_request_is_routed_to_a_listed_service : an_on_behalf_middleware
{
    void Establish()
    {
        _configuration.Value.OnBehalf!.Services = [OnBehalfConfiguration.ServiceName, "Billing"];
        RouteTo("billing");
        _sessions.Resolve(_context).Returns(new OnBehalfResolution(
            OnBehalfResolutionStatus.Active,
            new(Sessions.At(DateTimeOffset.UtcNow), Sessions.Represented(), "actor", "assertion")));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
    [Fact] void should_put_the_session_on_the_request() => _context.TryGetOnBehalf(out _).ShouldBeTrue();
    [Fact] void should_not_say_anything_was_refused() => _context.Response.Headers.ContainsKey(Headers.OnBehalfRefused).ShouldBeFalse();
}
