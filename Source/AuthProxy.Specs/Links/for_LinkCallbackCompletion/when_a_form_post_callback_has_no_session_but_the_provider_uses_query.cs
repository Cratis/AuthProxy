// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkCallbackCompletion.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Links.for_LinkCallbackCompletion;

/// <summary>
/// A POST callback to a provider that is not configured for a form post cannot be the cross-site case, so it is refused.
/// </summary>
public class when_a_form_post_callback_has_no_session_but_the_provider_uses_query : a_link_callback_context
{
    protected override bool HasSession => false;

    protected override string CallbackMethod => HttpMethods.Post;

    protected override C.OidcResponseMode ProviderResponseMode => C.OidcResponseMode.Query;

    async Task Because() => await LinkCallbackCompletion.Complete(_ticketContext, _properties);

    [Fact] void should_not_exchange_the_subject() =>
        _exchanger.DidNotReceiveWithAnyArgs().Exchange(Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>(), Arg.Any<string?>());
    [Fact] void should_answer_with_the_failure_status() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_handle_the_response() => _ticketContext.Result.Handled.ShouldBeTrue();
}
