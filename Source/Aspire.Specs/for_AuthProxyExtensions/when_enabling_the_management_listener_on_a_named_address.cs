// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

/// <summary>
/// A deployment whose probe genuinely runs elsewhere can widen the listener and rename the paths, and every
/// choice reaches the proxy verbatim.
/// </summary>
public class when_enabling_the_management_listener_on_a_named_address : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithManagementListener(9110, "0.0.0.0", "/internal/alive", "/internal/serving");

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_declare_the_bind_address() => _environment["Cratis__AuthProxy__Management__BindAddress"].ShouldEqual("0.0.0.0");
    [Fact] void should_declare_the_liveness_path() => _environment["Cratis__AuthProxy__Management__LivePath"].ShouldEqual("/internal/alive");
    [Fact] void should_declare_the_readiness_path() => _environment["Cratis__AuthProxy__Management__ReadyPath"].ShouldEqual("/internal/serving");
}
