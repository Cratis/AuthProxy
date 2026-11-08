// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy.given;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy;

/// <summary>
/// A deployment that declares no trusted proxies ignores forwarded headers from every peer.
/// </summary>
public class when_no_trusted_proxies_are_declared : a_trusted_proxy_policy
{
    readonly ForwardedHeadersOptions _options = new();

    void Because() => _policy.ApplyTo(_options);

    [Fact] void should_report_the_empty_boundary() => _policy.TrustsNoOne.ShouldBeTrue();
    [Fact] void should_ignore_forwarded_headers() => _options.ForwardedHeaders.ShouldEqual(ForwardedHeaders.None);
    [Fact] void should_not_trust_a_public_peer() => _policy.IsTrusted(IPAddress.Parse("198.51.100.10")).ShouldBeFalse();
    [Fact] void should_not_trust_a_private_peer() => _policy.IsTrusted(IPAddress.Parse("10.0.0.7")).ShouldBeFalse();
    [Fact] void should_not_trust_a_loopback_peer() => _policy.IsTrusted(IPAddress.Loopback).ShouldBeFalse();
    [Fact] void should_not_trust_an_unknown_peer() => _policy.IsTrusted(null).ShouldBeFalse();
    [Fact] void should_leave_the_middleware_with_no_known_networks() => _options.KnownIPNetworks.Count.ShouldEqual(0);
    [Fact] void should_leave_the_middleware_with_no_known_proxies() => _options.KnownProxies.Count.ShouldEqual(0);
}
