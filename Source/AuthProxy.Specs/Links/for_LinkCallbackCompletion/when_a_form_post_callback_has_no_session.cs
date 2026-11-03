// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkCallbackCompletion.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Links.for_LinkCallbackCompletion;

/// <summary>
/// A provider that answers with a cross-site form post does not send the session cookie with the callback.
/// The protected flow state, created only by a confirmed request from a signed-in session, carries the account
/// and the provider, so the comparison with the session is skipped when there is no session to compare with.
/// </summary>
public class when_a_form_post_callback_has_no_session : a_link_callback_context
{
    protected override bool HasSession => false;

    protected override string CallbackMethod => HttpMethods.Post;

    protected override C.OidcResponseMode ProviderResponseMode => C.OidcResponseMode.FormPost;

    async Task Because() => await LinkCallbackCompletion.Complete(_ticketContext, _properties);

    [Fact] void should_exchange_the_subject() =>
        _exchanger.Received(1).Exchange(Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>(), "github");
    [Fact] void should_redirect_to_the_return_url() => _context.Response.Headers.Location.ToString().ShouldEqual(ReturnUrl);
    [Fact] void should_handle_the_response() => _ticketContext.Result.Handled.ShouldBeTrue();
}
