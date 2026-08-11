// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

/// <summary>
/// A port that is not a port is refused where the app host is built, against the line of code that named
/// it, rather than being written into an environment variable and discovered at deployment.
/// </summary>
public class when_enabling_the_management_listener_on_an_unusable_port : given.an_auth_proxy_resource
{
    Exception _zero;
    Exception _negative;
    Exception _tooLarge;

    void Because()
    {
        _zero = Catch.Exception(() => _resource.WithManagementListener(0));
        _negative = Catch.Exception(() => _resource.WithManagementListener(-1));
        _tooLarge = Catch.Exception(() => _resource.WithManagementListener(70000));
    }

    [Fact] void should_refuse_an_ephemeral_port() => _zero.ShouldBeOfExactType<InvalidManagementPort>();
    [Fact] void should_refuse_a_negative_port() => _negative.ShouldBeOfExactType<InvalidManagementPort>();
    [Fact] void should_refuse_a_port_above_the_range() => _tooLarge.ShouldBeOfExactType<InvalidManagementPort>();
    [Fact] async Task should_declare_nothing() => (await EnvironmentVariables()).ShouldBeEmpty();
}
