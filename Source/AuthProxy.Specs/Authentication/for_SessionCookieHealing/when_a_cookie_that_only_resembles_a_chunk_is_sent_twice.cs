// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionCookieHealing;

public class when_a_cookie_that_only_resembles_a_chunk_is_sent_twice : given.a_browser_request
{
    bool _healed;

    void Establish()
    {
        _session.CookieDomain = ".example.test";
        SendCookies($"{Cookie}=session", $"{Cookie}Cx=one", $"{Cookie}Cx=two");
    }

    void Because() => _healed = SessionCookieHealing.DeleteDuplicatedHostOnlyCopy(_context, _session);

    [Fact] void should_not_treat_it_as_a_chunk() => _healed.ShouldBeFalse();
}
