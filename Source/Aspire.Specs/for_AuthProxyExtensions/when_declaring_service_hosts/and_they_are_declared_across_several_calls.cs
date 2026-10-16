// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_declaring_service_hosts;

/// <summary>
/// A second call appends rather than overwriting what the first one wrote, and each service is numbered on its own,
/// because indices are positions in a configuration array.
/// </summary>
public class and_they_are_declared_across_several_calls : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish()
    {
        _resource.WithHosts("console", "console.example.com");
        _resource.WithHosts("console", "www.example.com", "app.example.com");
        _resource.WithHosts("operations", "operations.example.com");
    }

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_keep_the_host_from_the_first_call() => _environment["Cratis__AuthProxy__Services__console__Hosts__0"].ShouldEqual("console.example.com");
    [Fact] void should_append_the_second_call_after_it() => _environment["Cratis__AuthProxy__Services__console__Hosts__1"].ShouldEqual("www.example.com");
    [Fact] void should_continue_appending_within_the_second_call() => _environment["Cratis__AuthProxy__Services__console__Hosts__2"].ShouldEqual("app.example.com");
    [Fact] void should_number_each_service_independently() => _environment["Cratis__AuthProxy__Services__operations__Hosts__0"].ShouldEqual("operations.example.com");
}
