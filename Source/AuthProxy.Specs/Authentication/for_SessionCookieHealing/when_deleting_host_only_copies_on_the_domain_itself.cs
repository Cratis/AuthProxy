// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionCookieHealing;

public class when_deleting_host_only_copies_on_the_domain_itself : given.a_browser_request
{
    void Establish()
    {
        _session.CookieDomain = ".example.test";
        _context.Request.Host = new HostString("example.test");
        SendCookies($"{Cookie}=session");
    }

    void Because() => SessionCookieHealing.DeleteHostOnlyCopies(_context, _session);

    [Fact] void should_delete_nothing_because_the_browser_may_not_tell_the_copies_apart() => SetCookies.ShouldBeEmpty();
}
