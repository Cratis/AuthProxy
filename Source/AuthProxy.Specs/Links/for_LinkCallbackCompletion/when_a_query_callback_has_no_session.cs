// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkCallbackCompletion.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Links.for_LinkCallbackCompletion;

/// <summary>
/// A redirect callback always carries the session cookie, so its absence means the session ended and the link must not complete.
/// </summary>
public class when_a_query_callback_has_no_session : a_link_callback_context
{
    protected override bool HasSession => false;

    protected override string CallbackMethod => HttpMethods.Get;

    protected override C.OidcResponseMode ProviderResponseMode => C.OidcResponseMode.Query;

    async Task Because() => await LinkCallbackCompletion.Complete(_ticketContext, _properties);

    [Fact] void should_not_exchange_the_subject() =>
        _exchanger.DidNotReceiveWithAnyArgs().Exchange(Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>(), Arg.Any<string?>());
    [Fact] void should_answer_with_the_failure_status() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_handle_the_response() => _ticketContext.Result.Handled.ShouldBeTrue();
}
