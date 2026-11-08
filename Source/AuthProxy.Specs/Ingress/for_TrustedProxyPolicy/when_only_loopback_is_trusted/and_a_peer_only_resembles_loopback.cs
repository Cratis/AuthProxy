// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy.given;

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy.when_only_loopback_is_trusted;

/// <summary>
/// Loopback means loopback: a caller one octet away, a private neighbor or a missing address is not it.
/// </summary>
public class and_a_peer_only_resembles_loopback : a_trusted_proxy_policy
{
    protected override C.Ingress Ingress => new() { Mode = C.TrustedProxyMode.LoopbackOnly, TrustedProxies = ["198.51.100.0/24"] };

    [Fact] void should_trust_the_ipv4_loopback_reported_ipv4_mapped() => _policy.IsTrusted(IPAddress.Loopback.MapToIPv6()).ShouldBeTrue();
    [Fact] void should_not_trust_the_address_after_the_loopback_network() => _policy.IsTrusted(IPAddress.Parse("128.0.0.1")).ShouldBeFalse();
    [Fact] void should_not_trust_the_address_before_the_loopback_network() => _policy.IsTrusted(IPAddress.Parse("126.255.255.255")).ShouldBeFalse();
    [Fact] void should_not_trust_a_private_peer() => _policy.IsTrusted(IPAddress.Parse("10.0.0.1")).ShouldBeFalse();
    [Fact] void should_not_trust_the_ipv6_unspecified_address() => _policy.IsTrusted(IPAddress.IPv6Any).ShouldBeFalse();
    [Fact] void should_not_trust_a_declared_proxy_while_the_mode_names_loopback_only() => _policy.IsTrusted(IPAddress.Parse("198.51.100.9")).ShouldBeFalse();
}
