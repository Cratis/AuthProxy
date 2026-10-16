// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionCookie;

public class when_nothing_is_configured : Specification
{
    CookieBuilder _cookie;

    void Establish() => _cookie = new CookieBuilder();

    void Because() => SessionCookie.Apply(_cookie, new C.Session());

    [Fact] void should_use_the_default_name() => _cookie.Name.ShouldEqual(".Cratis.AuthProxy.Auth.v2");
    [Fact] void should_be_host_only() => _cookie.Domain.ShouldBeNull();
}
