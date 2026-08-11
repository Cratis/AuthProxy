// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy.given;
using Microsoft.AspNetCore.Builder;

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyPolicy;

/// <summary>
/// The compatibility fallback: a deployment that declared nothing is left exactly as AuthProxy has always
/// behaved, and the fallback is reported so startup can say so.
/// </summary>
public class when_no_trusted_proxies_are_declared : a_trusted_proxy_policy
{
    readonly ForwardedHeadersOptions _options = new();

    void Because() => _policy.ApplyTo(_options);

    [Fact] void should_report_the_fallback() => _policy.IsLegacyAllowAll.ShouldBeTrue();
    [Fact] void should_believe_any_caller() => _policy.IsTrusted(IPAddress.Parse("198.51.100.10")).ShouldBeTrue();
    [Fact] void should_leave_the_middleware_with_no_known_networks() => _options.KnownIPNetworks.Count.ShouldEqual(0);
    [Fact] void should_leave_the_middleware_with_no_known_proxies() => _options.KnownProxies.Count.ShouldEqual(0);
}
