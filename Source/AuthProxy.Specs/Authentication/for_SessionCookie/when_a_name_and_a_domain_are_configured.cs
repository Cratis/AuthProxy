// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionCookie;

public class when_a_name_and_a_domain_are_configured : Specification
{
    CookieBuilder _cookie;

    void Establish() => _cookie = new CookieBuilder();

    void Because() => SessionCookie.Apply(_cookie, new C.Session { CookieName = " .Studio.Auth ", CookieDomain = " .example.test " });

    [Fact] void should_use_the_configured_name() => _cookie.Name.ShouldEqual(".Studio.Auth");
    [Fact] void should_use_the_configured_domain() => _cookie.Domain.ShouldEqual(".example.test");
}
