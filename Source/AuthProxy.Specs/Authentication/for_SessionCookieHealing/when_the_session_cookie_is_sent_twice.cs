// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionCookieHealing;

public class when_the_session_cookie_is_sent_twice : given.a_browser_request
{
    bool _healed;

    void Establish()
    {
        _session.CookieDomain = ".example.test";
        SendCookies($"{Cookie}=host-only", $"{Cookie}=domain", "unrelated=value");
    }

    void Because() => _healed = SessionCookieHealing.DeleteDuplicatedHostOnlyCopy(_context, _session);

    [Fact] void should_report_the_duplicate() => _healed.ShouldBeTrue();
    [Fact] void should_delete_the_host_only_copy() => Deleted(Cookie).ShouldBeTrue();
    [Fact] void should_never_name_the_domain() => DeletedWithDomain(Cookie).ShouldBeFalse();
}
