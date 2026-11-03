// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkCallbackCompletion.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Links.for_LinkCallbackCompletion;

public class when_the_session_cookie_is_absent_and_the_flow_has_no_binding : a_link_callback_context
{
    protected override bool HasSession => false;

    protected override ClaimsPrincipal? BoundPrincipal => null;

    async Task Because() => await LinkCallbackCompletion.Complete(_ticketContext, _properties);

    [Fact] void should_not_exchange_the_subject() =>
        _exchanger.DidNotReceiveWithAnyArgs().Exchange(Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>(), Arg.Any<string?>());
    [Fact] void should_answer_with_the_failure_status() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
}
