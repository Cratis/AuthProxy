// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy.given;

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy;

/// <summary>
/// A boundary written for one address family and one that ends inside an octet admit exactly what they name.
/// </summary>
public class when_a_boundary_is_declared_across_address_families : a_trusted_proxy_policy
{
    protected override C.Ingress Ingress => new() { TrustedProxies = ["2001:db8::/32", "198.51.100.0/31"] };

    [Fact] void should_trust_a_peer_inside_the_ipv6_range() => _policy.IsTrusted(IPAddress.Parse("2001:db8::1")).ShouldBeTrue();
    [Fact] void should_not_trust_a_peer_just_outside_the_ipv6_range() => _policy.IsTrusted(IPAddress.Parse("2001:db9::1")).ShouldBeFalse();
    [Fact] void should_not_trust_an_ipv4_peer_because_of_an_ipv6_range() => _policy.IsTrusted(IPAddress.Parse("32.1.13.184")).ShouldBeFalse();
    [Fact] void should_trust_the_first_address_of_a_range_ending_inside_an_octet() => _policy.IsTrusted(IPAddress.Parse("198.51.100.0")).ShouldBeTrue();
    [Fact] void should_trust_the_last_address_of_a_range_ending_inside_an_octet() => _policy.IsTrusted(IPAddress.Parse("198.51.100.1")).ShouldBeTrue();
    [Fact] void should_not_trust_the_address_after_a_range_ending_inside_an_octet() => _policy.IsTrusted(IPAddress.Parse("198.51.100.2")).ShouldBeFalse();
    [Fact] void should_not_trust_the_address_before_a_range_ending_inside_an_octet() => _policy.IsTrusted(IPAddress.Parse("198.51.99.255")).ShouldBeFalse();
    [Fact] void should_trust_the_range_when_the_peer_is_reported_ipv4_mapped() => _policy.IsTrusted(IPAddress.Parse("198.51.100.1").MapToIPv6()).ShouldBeTrue();
    [Fact] void should_not_trust_the_neighbor_when_the_peer_is_reported_ipv4_mapped() => _policy.IsTrusted(IPAddress.Parse("198.51.100.2").MapToIPv6()).ShouldBeFalse();
}
