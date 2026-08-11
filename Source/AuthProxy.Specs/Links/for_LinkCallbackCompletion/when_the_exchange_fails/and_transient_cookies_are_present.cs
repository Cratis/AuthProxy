// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Links.for_LinkCallbackCompletion.given;

namespace Cratis.AuthProxy.Links.for_LinkCallbackCompletion.when_the_exchange_fails;

/// <summary>
/// The provider callback clears the transient handshake cookies before it reaches the link branch, which is
/// what heals a browser poisoned by earlier half-cleared sessions. Establishing that cleared state and then
/// failing the exchange pins that the failure answer keeps it — a retry must not trip over the very cookies
/// the callback already deleted.
/// </summary>
public class and_transient_cookies_are_present : a_link_callback_context
{
    protected override LinkExchangeResult ExchangeResult => LinkExchangeResult.Failed;

    void Establish()
    {
        _context.Request.Headers.Cookie =
            $"{Cookies.CorrelationPrefix}abc=one; {Cookies.NoncePrefix}def=two; keep-me=value";
        TransientAuthenticationCookies.Clear(_context);
    }

    async Task Because() => await LinkCallbackCompletion.Complete(_ticketContext, _properties);

    [Fact] void should_keep_the_correlation_cookie_cleared() =>
        _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.CorrelationPrefix}abc=; expires");
    [Fact] void should_keep_the_nonce_cookie_cleared() =>
        _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.NoncePrefix}def=; expires");
    [Fact] void should_not_clear_unrelated_cookies() =>
        _context.Response.Headers.SetCookie.ToString().ShouldNotContain("keep-me=;");
    [Fact] void should_answer_with_a_non_success_status() =>
        _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
}
