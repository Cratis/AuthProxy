// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_a_confirmation_was_stored_while_the_endpoint_timed_out : given.a_confirmation_stored_while_the_endpoint_answers
{
    void Establish()
    {
        _lateStatus = null;
        _lateFailure = new TaskCanceledException("The tenant endpoint timed out");
    }

    async Task Because() => await RunInterleavedRequests();

    [Fact] void should_make_the_held_request_fail_closed() => _first.Response.StatusCode.ShouldEqual(StatusCodes.Status503ServiceUnavailable);
    [Fact] void should_not_confirm_a_tenant_for_the_held_request() => Confirmed(_first).ShouldEqual(string.Empty);
    [Fact] void should_have_confirmed_the_concurrent_request() => Confirmed(_second).ShouldEqual("tenant-a");
    [Fact] void should_have_stored_the_confirmation_before_the_held_request_answered() => _callsAfterProbe.ShouldEqual(_callsBeforeProbe);
    [Fact] void should_have_served_the_stored_confirmation_before_the_held_request_answered() => Confirmed(_probe).ShouldEqual("tenant-a");
    [Fact] void should_ask_the_tenant_endpoint_again_for_the_next_request() => _endpointCalls.ShouldEqual(_callsBeforeThird + 1);
    [Fact] void should_not_forward_the_next_request() => _nextCalledForThird.ShouldBeFalse();
    [Fact] void should_not_confirm_a_tenant_for_the_next_request() => Confirmed(_third).ShouldEqual(string.Empty);
}
