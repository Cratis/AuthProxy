// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

public class when_declaring_a_path_prefix : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish()
    {
        _resource.WithPathPrefix("reports", "/reports", stripPathPrefix: true);
        _resource.WithPathPrefix("billing", "/billing");
    }

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_declare_the_prefix() => _environment["Cratis__AuthProxy__Services__reports__PathPrefix"].ShouldEqual("/reports");
    [Fact] void should_declare_that_it_is_stripped_when_asked() => _environment["Cratis__AuthProxy__Services__reports__StripPathPrefix"].ShouldEqual("True");
    [Fact] void should_declare_the_prefix_of_another_service() => _environment["Cratis__AuthProxy__Services__billing__PathPrefix"].ShouldEqual("/billing");
    [Fact] void should_leave_the_prefix_in_place_unless_asked() => _environment.ContainsKey("Cratis__AuthProxy__Services__billing__StripPathPrefix").ShouldBeFalse();
}
