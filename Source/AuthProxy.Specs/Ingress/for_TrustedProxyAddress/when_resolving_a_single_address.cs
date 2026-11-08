// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyAddress;

/// <summary>
/// A bare address names exactly that address, for either family, and not a range that happens to contain it.
/// </summary>
public class when_resolving_a_single_address : Specification
{
    IPNetwork? _ipv4;
    IPNetwork? _ipv6;
    IPNetwork? _padded;

    void Because()
    {
        _ipv4 = TrustedProxyAddress.Resolve("203.0.113.7");
        _ipv6 = TrustedProxyAddress.Resolve("2001:db8::7");
        _padded = TrustedProxyAddress.Resolve("  203.0.113.7\t");
    }

    [Fact] void should_contain_the_ipv4_address() => _ipv4!.Value.Contains(IPAddress.Parse("203.0.113.7")).ShouldBeTrue();
    [Fact] void should_not_contain_the_next_ipv4_address() => _ipv4!.Value.Contains(IPAddress.Parse("203.0.113.8")).ShouldBeFalse();
    [Fact] void should_not_contain_the_previous_ipv4_address() => _ipv4!.Value.Contains(IPAddress.Parse("203.0.113.6")).ShouldBeFalse();
    [Fact] void should_contain_the_ipv6_address() => _ipv6!.Value.Contains(IPAddress.Parse("2001:db8::7")).ShouldBeTrue();
    [Fact] void should_not_contain_the_next_ipv6_address() => _ipv6!.Value.Contains(IPAddress.Parse("2001:db8::8")).ShouldBeFalse();
    [Fact] void should_ignore_surrounding_whitespace() => _padded.ShouldEqual(_ipv4);
}
