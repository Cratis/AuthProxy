// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Ingress.for_PublicAddress;

/// <summary>
/// Loopback, private, link-local and shared addresses are not public, including when written as IPv4-mapped IPv6.
/// </summary>
public class when_classifying_addresses : Specification
{
    static bool Public(string address) => AuthProxy.Ingress.PublicAddress.Is(IPAddress.Parse(address));

    [Fact] void should_treat_an_internet_address_as_public() => Public("198.51.100.10").ShouldBeTrue();
    [Fact] void should_treat_a_public_ipv6_address_as_public() => Public("2001:db8::1").ShouldBeTrue();
    [Fact] void should_treat_a_mapped_public_address_as_public() => Public("::ffff:198.51.100.10").ShouldBeTrue();
    [Fact] void should_not_treat_loopback_as_public() => Public("127.0.0.1").ShouldBeFalse();
    [Fact] void should_not_treat_private_ranges_as_public() => new[] { "10.1.2.3", "172.16.0.1", "172.31.255.1", "192.168.1.1" }.Any(Public).ShouldBeFalse();
    [Fact] void should_treat_addresses_just_outside_the_172_range_as_public() => new[] { "172.15.0.1", "172.32.0.1" }.All(Public).ShouldBeTrue();
    [Fact] void should_not_treat_link_local_as_public() => Public("169.254.1.1").ShouldBeFalse();
    [Fact] void should_not_treat_shared_address_space_as_public() => Public("100.64.0.1").ShouldBeFalse();
    [Fact] void should_not_treat_a_mapped_private_address_as_public() => Public("::ffff:10.0.0.7").ShouldBeFalse();
    [Fact] void should_not_treat_unique_local_ipv6_as_public() => Public("fd00::1").ShouldBeFalse();
    [Fact] void should_not_treat_link_local_ipv6_as_public() => Public("fe80::1").ShouldBeFalse();
    [Fact] void should_not_treat_a_missing_address_as_public() => AuthProxy.Ingress.PublicAddress.Is(null).ShouldBeFalse();
}
