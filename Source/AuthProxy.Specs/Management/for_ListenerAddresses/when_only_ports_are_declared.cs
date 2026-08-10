// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Management.for_ListenerAddresses;

/// <summary>
/// The one that matters in production. The official .NET container images publish their port through
/// <c>ASPNETCORE_HTTP_PORTS</c> and set no <c>ASPNETCORE_URLS</c> at all, so a resolution that read only
/// the URLs would conclude that a deployed AuthProxy listens on nothing — and re-declaring "nothing plus
/// the management listener" would take the whole proxy off the network.
/// </summary>
public class when_only_ports_are_declared : Specification
{
    ListenerAddresses _addresses;

    void Because() => _addresses = ListenerAddresses.Resolve(new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["http_ports"] = "8080",
            ["https_ports"] = "8443"
        })
        .Build());

    [Fact] void should_expand_the_http_port() => _addresses.Declared.ShouldContain("http://*:8080");
    [Fact] void should_expand_the_https_port() => _addresses.Declared.ShouldContain("https://*:8443");
    [Fact] void should_recognize_the_published_port() => _addresses.Uses(8080).ShouldBeTrue();
    [Fact] void should_not_fall_back_to_the_host_default() => _addresses.Declared.ShouldNotContain(ListenerAddresses.HostDefault);
}
