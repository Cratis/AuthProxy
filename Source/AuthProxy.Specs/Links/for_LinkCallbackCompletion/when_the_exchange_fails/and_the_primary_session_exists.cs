// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkCallbackCompletion.given;

namespace Cratis.AuthProxy.Links.for_LinkCallbackCompletion.when_the_exchange_fails;

/// <summary>
/// The hazard spec. A link callback carries a <em>second</em> identity, and the remote authentication
/// handler's default behavior is to sign whatever ticket it holds into the primary cookie scheme. The only
/// thing that stops it is the response being handled here, on both outcomes — so an obvious "fix" that
/// answers the failure without short-circuiting silently converts a failed credential link into an account
/// swap: the person comes back signed in as somebody else.
/// </summary>
public class and_the_primary_session_exists : a_link_callback_context
{
    const string PrimaryAuthenticationCookie = ".Cratis.AuthProxy.Auth.v2";

    protected override LinkExchangeResult ExchangeResult => LinkExchangeResult.Failed;

    void Establish() =>
        _context.Request.Headers.Cookie = $"{PrimaryAuthenticationCookie}=an-existing-primary-session";

    async Task Because() => await LinkCallbackCompletion.Complete(_ticketContext, _properties);

    [Fact] void should_not_replace_the_primary_session() => _ticketContext.Result.Handled.ShouldBeTrue();
    [Fact] void should_not_write_the_primary_authentication_cookie() =>
        _context.Response.Headers.SetCookie.ToString().ShouldNotContain(PrimaryAuthenticationCookie);
    [Fact] void should_not_notify_the_application_of_a_sign_in() =>
        _signInNotifier.DidNotReceive().Notify(Arg.Any<HttpContext>(), Arg.Any<ClaimsPrincipal>());
    [Fact] void should_not_resolve_a_post_authentication_redirect() => _ticketContext.ReturnUri.ShouldBeNull();
}
