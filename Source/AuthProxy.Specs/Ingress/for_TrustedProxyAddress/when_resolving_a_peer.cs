// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyAddress;

/// <summary>
/// A bare address names the network containing only itself, so matching a peer is one operation whatever the
/// deployment wrote.
/// </summary>
public class when_resolving_a_peer : Specification
{
    System.Net.IPNetwork? _fromIPv4;
    System.Net.IPNetwork? _fromIPv6;

    void Because()
    {
        _fromIPv4 = TrustedProxyAddress.Resolve(" 203.0.113.7 ");
        _fromIPv6 = TrustedProxyAddress.Resolve("2001:db8::1");
    }

    [Fact] void should_contain_the_declared_address() => _fromIPv4!.Value.Contains(IPAddress.Parse("203.0.113.7")).ShouldBeTrue();
    [Fact] void should_contain_nothing_else() => _fromIPv4!.Value.Contains(IPAddress.Parse("203.0.113.8")).ShouldBeFalse();
    [Fact] void should_contain_the_declared_ipv6_address() => _fromIPv6!.Value.Contains(IPAddress.Parse("2001:db8::1")).ShouldBeTrue();
    [Fact] void should_contain_no_other_ipv6_address() => _fromIPv6!.Value.Contains(IPAddress.Parse("2001:db8::2")).ShouldBeFalse();
}
