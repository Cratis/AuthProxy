// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyAddress;

/// <summary>
/// Entries that name no network are refused rather than guessed at.
/// </summary>
/// <remarks>
/// A host name is the one worth stating outright: it is the natural thing to reach for when the ingress is
/// known by name rather than by address, and resolving it would move the boundary every time DNS moved.
/// </remarks>
public class when_resolving_something_that_names_no_network : Specification
{
    [Fact] void should_refuse_a_host_name() => TrustedProxyAddress.Resolve("ingress.example.com").ShouldBeNull();
    [Fact] void should_refuse_an_address_with_a_port() => TrustedProxyAddress.Resolve("10.0.0.7:443").ShouldBeNull();
    [Fact] void should_refuse_an_out_of_range_prefix() => TrustedProxyAddress.Resolve("10.0.0.0/64").ShouldBeNull();
    [Fact] void should_refuse_nothing_at_all() => TrustedProxyAddress.Resolve("   ").ShouldBeNull();
}
