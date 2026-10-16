// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionConfigurationWarnings;

public class when_the_domain_is_set_while_every_host_is_allowed : Specification
{
    string[] _warnings;

    void Because() => _warnings = [.. SessionConfigurationWarnings.Describe(new C.Session { CookieDomain = ".example.test" }, ["*"])];

    [Fact] void should_warn_once() => _warnings.Length.ShouldEqual(1);
    [Fact] void should_name_allowed_hosts() => _warnings[0].ShouldContain("AllowedHosts");
}
