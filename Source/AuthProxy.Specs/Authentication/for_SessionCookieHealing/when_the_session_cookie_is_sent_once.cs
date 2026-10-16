// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionCookieHealing;

public class when_the_session_cookie_is_sent_once : given.a_browser_request
{
    bool _healed;

    void Establish()
    {
        _session.CookieDomain = ".example.test";
        SendCookies($"{Cookie}=chunks-1", $"{Cookie}C1=first");
    }

    void Because() => _healed = SessionCookieHealing.DeleteDuplicatedHostOnlyCopy(_context, _session);

    [Fact] void should_report_no_duplicate() => _healed.ShouldBeFalse();
    [Fact] void should_delete_nothing() => SetCookies.ShouldBeEmpty();
}
