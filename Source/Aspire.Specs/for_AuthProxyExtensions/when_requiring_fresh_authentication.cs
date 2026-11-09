// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

public class when_requiring_fresh_authentication : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish()
    {
        _resource.WithFreshAuthentication("main", "/approve", TimeSpan.FromMinutes(2), false, "POST");
        _resource.WithFreshAuthentication("main", "/admin", prefix: true);
    }

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_write_the_path() => _environment["Cratis__AuthProxy__Services__main__FreshAuthentication__0__Path"].ShouldEqual("/approve");
    [Fact] void should_write_the_age() => _environment["Cratis__AuthProxy__Services__main__FreshAuthentication__0__MaxAge"].ShouldEqual("00:02:00");
    [Fact] void should_write_the_method() => _environment["Cratis__AuthProxy__Services__main__FreshAuthentication__0__Methods__0"].ShouldEqual("POST");
    [Fact] void should_append_later_rules() => _environment["Cratis__AuthProxy__Services__main__FreshAuthentication__1__Prefix"].ShouldEqual("True");
    [Fact] void should_default_to_five_minutes() => _environment["Cratis__AuthProxy__Services__main__FreshAuthentication__1__MaxAge"].ShouldEqual("00:05:00");
}
