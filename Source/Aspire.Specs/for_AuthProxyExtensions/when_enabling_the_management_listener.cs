// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

/// <summary>
/// Opening the management listener is its own builder rather than another optional argument on
/// <c>AddAuthProxy</c>, and it writes exactly the four keys the proxy reads.
/// <para>
/// The Aspire package cannot reference the proxy it configures, so these strings are the only thing joining
/// the two. A rename on either side binds nothing and falls back to a default — which for the port, the one
/// setting with no default, means no listener at all and every probe failing to connect.
/// </para>
/// </summary>
public class when_enabling_the_management_listener : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithManagementListener(9110);

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_declare_the_port() => _environment["Cratis__AuthProxy__Management__Port"].ShouldEqual("9110");
    [Fact] void should_keep_the_listener_on_loopback() => _environment["Cratis__AuthProxy__Management__BindAddress"].ShouldEqual("127.0.0.1");
    [Fact] void should_declare_the_liveness_path() => _environment["Cratis__AuthProxy__Management__LivePath"].ShouldEqual("/health/live");
    [Fact] void should_declare_the_readiness_path() => _environment["Cratis__AuthProxy__Management__ReadyPath"].ShouldEqual("/health/ready");
    [Fact] void should_leave_the_services_alone() => _environment.Keys.Any(_ => _.Contains("__Services__", StringComparison.Ordinal)).ShouldBeFalse();
}
