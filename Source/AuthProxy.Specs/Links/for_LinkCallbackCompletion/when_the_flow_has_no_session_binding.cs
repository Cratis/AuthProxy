// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkCallbackCompletion.given;

namespace Cratis.AuthProxy.Links.for_LinkCallbackCompletion;

public class when_the_flow_has_no_session_binding : a_link_callback_context
{
    protected override ClaimsPrincipal? BoundPrincipal => null;

    async Task Because() => await LinkCallbackCompletion.Complete(_ticketContext, _properties);

    [Fact] void should_not_exchange_the_subject() =>
        _exchanger.DidNotReceiveWithAnyArgs().Exchange(default!, default!, default);
    [Fact] void should_answer_with_the_failure_status() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_not_redirect() => _context.Response.Headers.Location.ToString().ShouldEqual(string.Empty);
    [Fact] void should_handle_the_response() => _ticketContext.Result.Handled.ShouldBeTrue();
}
