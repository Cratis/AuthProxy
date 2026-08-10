// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy.given;

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy;

/// <summary>
/// A declared boundary admits the deployment's own infrastructure and nothing else.
/// </summary>
/// <remarks>
/// The IPv4-mapped case is the one that silently ruins a correct configuration: a dual-stack listener reports
/// an IPv4 peer as <c>::ffff:10.0.0.7</c>, so an operator who declared <c>10.0.0.0/8</c> would see none of
/// their own traffic match, conclude the setting does not work, and reach for the allow-all fallback.
/// </remarks>
public class when_matching_a_peer_against_declared_proxies : a_trusted_proxy_policy
{
    protected override C.Ingress Ingress => new() { TrustedProxies = ["10.0.0.0/8", "203.0.113.7"] };

    [Fact] void should_trust_a_peer_inside_a_declared_range() => _policy.IsTrusted(IPAddress.Parse("10.4.5.6")).ShouldBeTrue();
    [Fact] void should_trust_a_declared_peer() => _policy.IsTrusted(IPAddress.Parse("203.0.113.7")).ShouldBeTrue();
    [Fact] void should_not_trust_a_peer_outside_every_declared_range() => _policy.IsTrusted(IPAddress.Parse("198.51.100.10")).ShouldBeFalse();
    [Fact] void should_not_trust_a_neighbor_of_a_declared_peer() => _policy.IsTrusted(IPAddress.Parse("203.0.113.8")).ShouldBeFalse();
    [Fact] void should_trust_a_declared_range_reported_as_ipv4_mapped() => _policy.IsTrusted(IPAddress.Parse("10.4.5.6").MapToIPv6()).ShouldBeTrue();
    [Fact] void should_not_trust_an_unknown_peer_reported_as_ipv4_mapped() => _policy.IsTrusted(IPAddress.Parse("198.51.100.10").MapToIPv6()).ShouldBeFalse();
    [Fact] void should_not_trust_a_caller_with_no_address_at_all() => _policy.IsTrusted(null).ShouldBeFalse();
    [Fact] void should_not_report_the_legacy_fallback() => _policy.IsLegacyAllowAll.ShouldBeFalse();
}
