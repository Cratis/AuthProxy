// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionCookieHealing;

public class when_a_chunk_of_the_session_cookie_is_sent_twice : given.a_browser_request
{
    bool _healed;

    void Establish()
    {
        _session.CookieDomain = ".example.test";
        SendCookies($"{Cookie}=chunks-2", $"{Cookie}C1=old", $"{Cookie}C1=new", $"{Cookie}C2=second");
    }

    void Because() => _healed = SessionCookieHealing.DeleteDuplicatedHostOnlyCopy(_context, _session);

    [Fact] void should_report_the_duplicate() => _healed.ShouldBeTrue();
    [Fact] void should_delete_the_session_cookie() => Deleted(Cookie).ShouldBeTrue();
    [Fact] void should_delete_every_chunk() => (Deleted($"{Cookie}C1") && Deleted($"{Cookie}C2")).ShouldBeTrue();
}
