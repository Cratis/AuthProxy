// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionConfigurationWarnings;

public class when_the_cookie_name_has_the_secure_prefix : Specification
{
    string[] _warnings;

    void Because() => _warnings = [.. SessionConfigurationWarnings.Describe(new C.Session { CookieName = "__Secure-session" }, ["host.test"])];

    [Fact] void should_warn_once() => _warnings.Length.ShouldEqual(1);
    [Fact] void should_name_the_prefix() => _warnings[0].ShouldContain("__Secure-");
}
