// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_declaring_trusted_proxies;

/// <summary>
/// A peer the proxy will not be able to resolve is refused where the app host declares it.
/// </summary>
/// <remarks>
/// AuthProxy refuses the same value at startup, so this only moves the discovery from a deployment to a run
/// of the app host — against the line of code that made the mistake, rather than against a container log.
/// </remarks>
public class and_one_of_them_names_no_network : given.an_auth_proxy_resource
{
    Exception? _exception;

    void Because() => _exception = Record.Exception(
        () => _resource.WithTrustedProxies("10.0.0.0/8", "ingress.example.com"));

    [Fact] void should_refuse_it() => _exception.ShouldBeOfExactType<InvalidTrustedProxy>();
    [Fact] void should_name_the_offending_value() => _exception!.Message.ShouldContain("ingress.example.com");
}
