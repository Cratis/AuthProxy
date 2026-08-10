// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy.given;

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy;

public class when_only_loopback_is_trusted : a_trusted_proxy_policy
{
    protected override C.Ingress Ingress => new() { Mode = C.TrustedProxyMode.LoopbackOnly };

    [Fact] void should_trust_the_loopback_address() => _policy.IsTrusted(IPAddress.Loopback).ShouldBeTrue();
    [Fact] void should_trust_the_ipv6_loopback_address() => _policy.IsTrusted(IPAddress.IPv6Loopback).ShouldBeTrue();
    [Fact] void should_not_trust_anything_else() => _policy.IsTrusted(IPAddress.Parse("10.4.5.6")).ShouldBeFalse();
    [Fact] void should_not_report_the_legacy_fallback() => _policy.IsLegacyAllowAll.ShouldBeFalse();
}
