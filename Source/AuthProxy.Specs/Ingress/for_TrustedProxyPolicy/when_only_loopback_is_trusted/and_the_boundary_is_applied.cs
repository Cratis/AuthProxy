// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy.given;
using Microsoft.AspNetCore.Builder;

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy.when_only_loopback_is_trusted;

/// <summary>
/// <c>LoopbackOnly</c> used to be expressed by returning without touching the options, on the reasoning that
/// loopback is the framework's own default and there was nothing to add. That reasoning holds only while the
/// defaults are still there, and they are not always: <c>ASPNETCORE_FORWARDEDHEADERS_ENABLED</c>, the
/// standard switch for containerized ASP.NET images, has <c>ConfigureWebDefaults</c> clear both lists — and
/// the forwarded-headers middleware treats two empty lists as "believe every caller", the exact opposite of
/// the mode's name. A mode that names a boundary has to write the boundary down.
/// </summary>
public class and_the_boundary_is_applied : a_trusted_proxy_policy
{
    protected override C.Ingress Ingress => new() { Mode = C.TrustedProxyMode.LoopbackOnly };

    readonly ForwardedHeadersOptions _options = new();

    void Establish()
    {
        // The state the environment switch leaves behind: nothing known, and therefore everything believed.
        _options.KnownIPNetworks.Clear();
        _options.KnownProxies.Clear();
    }

    void Because() => _policy.ApplyTo(_options);

    [Fact] void should_name_a_boundary_rather_than_inherit_one() =>
        (_options.KnownIPNetworks.Count + _options.KnownProxies.Count).ShouldBeGreaterThan(0);

    [Fact] void should_know_the_ipv4_loopback_network() =>
        _options.KnownIPNetworks.Any(network => network.Contains(IPAddress.Loopback)).ShouldBeTrue();

    [Fact] void should_know_the_ipv6_loopback_address() =>
        _options.KnownProxies.Contains(IPAddress.IPv6Loopback).ShouldBeTrue();

    [Fact] void should_not_know_anything_else() =>
        _options.KnownIPNetworks.Any(network => network.Contains(IPAddress.Parse("10.4.5.6"))).ShouldBeFalse();
}
