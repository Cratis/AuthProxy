// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_declaring_trusted_proxies;

/// <summary>
/// The declared peers land on the configuration keys the proxy binds, and a second call appends rather than
/// overwriting what the first one wrote.
/// </summary>
/// <remarks>
/// Indices are positions in a configuration array, so a call that restarted at zero would silently drop the
/// earlier peers — and a dropped trusted proxy is not a missing feature but a boundary in the wrong place:
/// the ingress the app host thought it had declared would have its forwarded headers refused, while the
/// deployment reads as configured.
/// </remarks>
public class and_they_are_declared_across_several_calls : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish()
    {
        _resource.WithTrustedProxies("10.0.0.0/8");
        _resource.WithTrustedProxies("203.0.113.7", "2001:db8::/32");
        _resource.WithForwardLimit(2);
    }

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_keep_the_peer_from_the_first_call() => _environment["Cratis__AuthProxy__Ingress__TrustedProxies__0"].ShouldEqual("10.0.0.0/8");
    [Fact] void should_append_the_second_call_after_it() => _environment["Cratis__AuthProxy__Ingress__TrustedProxies__1"].ShouldEqual("203.0.113.7");
    [Fact] void should_continue_appending_within_the_second_call() => _environment["Cratis__AuthProxy__Ingress__TrustedProxies__2"].ShouldEqual("2001:db8::/32");
    [Fact] void should_write_one_variable_per_declared_peer() => _environment.Keys.Count(_ => _.Contains("TrustedProxies", StringComparison.Ordinal)).ShouldEqual(3);
    [Fact] void should_write_the_forward_limit() => _environment["Cratis__AuthProxy__Ingress__ForwardLimit"].ShouldEqual("2");
}
