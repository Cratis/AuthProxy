// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_IngressExtensions.given;
using Cratis.AuthProxy.Ingress;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.for_IngressExtensions;

/// <summary>
/// Asking for loopback-only restores the framework's own default, which the proxy used to delete outright.
/// </summary>
public class when_only_loopback_is_trusted : an_ingress_configuration
{
    ForwardedHeadersOptions _options;

    protected override IDictionary<string, string?> IngressSettings => new Dictionary<string, string?>
    {
        [$"{C.Ingress.SectionKey}:Mode"] = nameof(C.TrustedProxyMode.LoopbackOnly),
    };

    void Because() => _options = _serviceProvider.GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value;

    [Fact] void should_keep_a_peer_check() => (_options.KnownIPNetworks.Count + _options.KnownProxies.Count > 0).ShouldBeTrue();
    [Fact] void should_not_report_the_legacy_allow_all_fallback() => _serviceProvider.GetRequiredService<ITrustedProxyPolicy>().IsLegacyAllowAll.ShouldBeFalse();
}
