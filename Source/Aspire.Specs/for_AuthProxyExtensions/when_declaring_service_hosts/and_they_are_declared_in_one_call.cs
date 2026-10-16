// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_declaring_service_hosts;

/// <summary>
/// Declared hosts reach the proxy as the indexed environment variables its configuration binds to the service's
/// host list. A wrong key silently produces a proxy that claims no host, and the first sign of it is a host that
/// routes nothing.
/// </summary>
public class and_they_are_declared_in_one_call : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithHosts("console", "console.example.com", "console.example.com:8443");

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_write_the_first_host_at_the_first_index() => _environment["Cratis__AuthProxy__Services__console__Hosts__0"].ShouldEqual("console.example.com");
    [Fact] void should_write_the_second_host_at_the_second_index() => _environment["Cratis__AuthProxy__Services__console__Hosts__1"].ShouldEqual("console.example.com:8443");
    [Fact] void should_write_one_variable_per_host() => _environment.Keys.Count(_ => _.Contains("__Hosts__", StringComparison.Ordinal)).ShouldEqual(2);
}
