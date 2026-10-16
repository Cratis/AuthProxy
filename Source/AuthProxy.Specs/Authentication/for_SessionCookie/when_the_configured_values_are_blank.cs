// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionCookie;

public class when_the_configured_values_are_blank : Specification
{
    CookieBuilder _cookie;

    void Establish() => _cookie = new CookieBuilder();

    void Because() => SessionCookie.Apply(_cookie, new C.Session { CookieName = "", CookieDomain = "  " });

    [Fact] void should_fall_back_to_the_default_name() => _cookie.Name.ShouldEqual(C.Session.DefaultCookieName);
    [Fact] void should_stay_host_only() => _cookie.Domain.ShouldBeNull();
}
