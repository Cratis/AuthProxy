// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Management.for_ListenerAddresses;

/// <summary>
/// <c>ASPNETCORE_URLS</c> is the highest-priority answer, and several of them are separated by semicolons.
/// </summary>
public class when_urls_are_declared : Specification
{
    ListenerAddresses _addresses;

    void Because() => _addresses = ListenerAddresses.Resolve(new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["urls"] = "http://+:8080;https://+:8443",
            ["http_ports"] = "9999"
        })
        .Build());

    [Fact] void should_resolve_both_declared_addresses() => _addresses.Declared.ShouldContainOnly(["http://+:8080", "https://+:8443"]);
    [Fact] void should_ignore_the_lower_priority_ports_setting() => _addresses.Uses(9999).ShouldBeFalse();
    [Fact] void should_recognize_the_public_port() => _addresses.Uses(8080).ShouldBeTrue();
    [Fact] void should_recognize_the_secure_public_port() => _addresses.Uses(8443).ShouldBeTrue();
    [Fact] void should_not_recognize_a_free_port() => _addresses.Uses(9110).ShouldBeFalse();
    [Fact] void should_add_a_listener_without_dropping_the_existing_ones() => _addresses.Including("http://127.0.0.1:9110").ShouldContainOnly(["http://+:8080", "https://+:8443", "http://127.0.0.1:9110"]);
}
