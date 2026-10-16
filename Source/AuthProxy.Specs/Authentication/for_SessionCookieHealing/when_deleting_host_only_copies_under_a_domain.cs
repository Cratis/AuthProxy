// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionCookieHealing;

public class when_deleting_host_only_copies_under_a_domain : given.a_browser_request
{
    void Establish()
    {
        _session.CookieDomain = ".example.test";
        SendCookies($"{Cookie}=chunks-2", $"{Cookie}C1=first", $"{Cookie}C2=second", "unrelated=value");
    }

    void Because() => SessionCookieHealing.DeleteHostOnlyCopies(_context, _session);

    [Fact] void should_delete_the_session_cookie() => Deleted(Cookie).ShouldBeTrue();
    [Fact] void should_delete_the_first_chunk() => Deleted($"{Cookie}C1").ShouldBeTrue();
    [Fact] void should_delete_the_second_chunk() => Deleted($"{Cookie}C2").ShouldBeTrue();
    [Fact] void should_leave_unrelated_cookies_alone() => Deleted("unrelated").ShouldBeFalse();
    [Fact] void should_never_name_the_domain_so_the_shared_cookie_survives() => DeletedWithDomain(Cookie).ShouldBeFalse();
}
