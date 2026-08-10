// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_IngressExtensions.given;
using Cratis.AuthProxy.Ingress;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.for_IngressExtensions;

/// <summary>
/// A declared boundary reaches the forwarded-headers middleware, which is the only place it does anything.
/// </summary>
/// <remarks>
/// The middleware runs its peer check only when it knows at least one proxy or network, so a boundary that
/// was bound into configuration but never handed to the middleware would leave the proxy believing every
/// caller while the deployment's configuration said otherwise — the exact failure this whole change exists to
/// close, in a shape that reads as configured.
/// </remarks>
public class when_trusted_proxies_are_configured : an_ingress_configuration
{
    ForwardedHeadersOptions _options;

    protected override IDictionary<string, string?> IngressSettings => new Dictionary<string, string?>
    {
        [$"{C.Ingress.SectionKey}:TrustedProxies:0"] = "10.0.0.0/8",
        [$"{C.Ingress.SectionKey}:TrustedProxies:1"] = "203.0.113.7",
        [$"{C.Ingress.SectionKey}:ForwardLimit"] = "3",
    };

    void Because() => _options = _serviceProvider.GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value;

    [Fact] void should_know_every_declared_peer() => _options.KnownIPNetworks.Count.ShouldEqual(2);
    [Fact] void should_bind_the_forward_limit() => _options.ForwardLimit.ShouldEqual(3);
    [Fact] void should_still_consume_only_the_address_and_scheme() => _options.ForwardedHeaders.ShouldEqual(ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto);
    [Fact] void should_not_report_the_legacy_allow_all_fallback() => _serviceProvider.GetRequiredService<ITrustedProxyPolicy>().IsLegacyAllowAll.ShouldBeFalse();
}
