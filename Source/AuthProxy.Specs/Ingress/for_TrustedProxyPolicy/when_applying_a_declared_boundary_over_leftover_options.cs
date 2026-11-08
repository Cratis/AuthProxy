// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy.given;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy;

/// <summary>
/// The middleware keeps whatever it was handed, so a declared boundary must replace what an earlier
/// configuration left behind, narrow the headers believed to the two that matter, and apply the hop limit.
/// </summary>
public class when_applying_a_declared_boundary_over_leftover_options : a_trusted_proxy_policy
{
    protected override C.Ingress Ingress => new() { TrustedProxies = ["10.0.0.0/8"], ForwardLimit = 3 };

    readonly ForwardedHeadersOptions _options = new();

    void Establish()
    {
        _options.ForwardedHeaders = ForwardedHeaders.All;
        _options.ForwardLimit = null;
        _options.KnownProxies.Add(IPAddress.Parse("198.51.100.99"));
        _options.KnownIPNetworks.Add(new System.Net.IPNetwork(IPAddress.Any, 0));
    }

    void Because() => _policy.ApplyTo(_options);

    [Fact] void should_apply_the_declared_hop_limit() => _options.ForwardLimit.ShouldEqual(3);
    [Fact] void should_believe_only_the_forwarded_address_and_scheme() => _options.ForwardedHeaders.ShouldEqual(ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto);
    [Fact] void should_not_believe_a_forwarded_host() => _options.ForwardedHeaders.HasFlag(ForwardedHeaders.XForwardedHost).ShouldBeFalse();
    [Fact] void should_not_believe_a_forwarded_prefix() => _options.ForwardedHeaders.HasFlag(ForwardedHeaders.XForwardedPrefix).ShouldBeFalse();
    [Fact] void should_drop_a_leftover_known_proxy() => _options.KnownProxies.ShouldBeEmpty();
    [Fact] void should_drop_a_leftover_allow_all_network() => _options.KnownIPNetworks.Any(network => network.Contains(IPAddress.Parse("198.51.100.99"))).ShouldBeFalse();
    [Fact] void should_know_exactly_the_declared_network() => _options.KnownIPNetworks.Count.ShouldEqual(1);
}
