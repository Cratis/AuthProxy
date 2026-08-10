// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management.for_ManagementConfigurationValidator;

/// <summary>
/// Naming the port the proxy already serves traffic on is refused, because a private listener that shares
/// the public one is not private. Nothing about the running process would say so: the endpoints would
/// simply answer, to everyone the proxy is reachable from.
/// </summary>
public class when_the_port_is_the_public_one : given.a_deployment_listening_on_the_public_port
{
    void Because() => Validate(new C.Management { Port = PublicPort });

    [Fact] void should_fail_validation() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_port_key() => _result.Failures.ShouldContain(_ => _.Contains("Cratis:AuthProxy:Management:Port", StringComparison.Ordinal));
    [Fact] void should_name_the_offending_value() => _result.Failures.ShouldContain(_ => _.Contains("8080", StringComparison.Ordinal));
}
