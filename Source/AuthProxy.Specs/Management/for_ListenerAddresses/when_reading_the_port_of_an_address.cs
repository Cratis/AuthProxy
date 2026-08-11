// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management.for_ListenerAddresses;

/// <summary>
/// Whether a requested management port collides with the public listener is decided by reading the port out
/// of every shape an address is written in. A wildcard host, a bracketed IPv6 host and a trailing path all
/// appear in real deployments, and misreading any of them turns the collision check into a coin toss.
/// </summary>
public class when_reading_the_port_of_an_address : Specification
{
    [Fact] void should_read_a_wildcard_host() => ListenerAddresses.PortOf("http://+:8080").ShouldEqual(8080);
    [Fact] void should_read_a_star_host() => ListenerAddresses.PortOf("https://*:8443").ShouldEqual(8443);
    [Fact] void should_read_a_named_host() => ListenerAddresses.PortOf("http://localhost:5000").ShouldEqual(5000);
    [Fact] void should_read_an_ipv6_host() => ListenerAddresses.PortOf("http://[::1]:9110").ShouldEqual(9110);
    [Fact] void should_read_past_a_trailing_path() => ListenerAddresses.PortOf("http://127.0.0.1:9110/").ShouldEqual(9110);
    [Fact] void should_report_no_port_for_an_ipv6_host_without_one() => ListenerAddresses.PortOf("http://[::1]").ShouldBeNull();
    [Fact] void should_report_no_port_for_a_host_without_one() => ListenerAddresses.PortOf("http://localhost").ShouldBeNull();
}
