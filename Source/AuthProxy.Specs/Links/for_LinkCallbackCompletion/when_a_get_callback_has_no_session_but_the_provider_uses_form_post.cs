// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkCallbackCompletion.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Links.for_LinkCallbackCompletion;

/// <summary>
/// A form-post provider whose callback arrives as a GET is not the cross-site case, so it is refused.
/// </summary>
public class when_a_get_callback_has_no_session_but_the_provider_uses_form_post : a_link_callback_context
{
    protected override bool HasSession => false;

    protected override string CallbackMethod => HttpMethods.Get;

    protected override C.OidcResponseMode ProviderResponseMode => C.OidcResponseMode.FormPost;

    async Task Because() => await LinkCallbackCompletion.Complete(_ticketContext, _properties);

    [Fact] void should_not_exchange_the_subject() =>
        _exchanger.DidNotReceiveWithAnyArgs().Exchange(Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>(), Arg.Any<string?>());
    [Fact] void should_answer_with_the_failure_status() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_handle_the_response() => _ticketContext.Result.Handled.ShouldBeTrue();
}
