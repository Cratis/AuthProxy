// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkCallbackCompletion.given;

namespace Cratis.AuthProxy.Links.for_LinkCallbackCompletion.when_the_exchange_succeeds;

/// <summary>
/// The return URL travels in protected authentication state, which is why it is tempting to hand it to the
/// browser unexamined. It is validated all the same — an open redirect on the authentication proxy is the
/// strongest phishing primitive the system can offer, and this callback runs immediately after a real login
/// at a real identity provider.
/// </summary>
public class and_the_return_url_is_hostile : a_link_callback_context
{
    protected override string? RecordedReturnUrl => "//evil.test/link";

    async Task Because() => await LinkCallbackCompletion.Complete(_ticketContext, _properties);

    [Fact] void should_redirect_to_the_completion_page() =>
        _context.Response.Headers.Location.ToString().ShouldEqual(WellKnownPaths.LinkComplete);
    [Fact] void should_not_send_the_browser_off_site() =>
        _context.Response.Headers.Location.ToString().ShouldNotContain("evil.test");
}
