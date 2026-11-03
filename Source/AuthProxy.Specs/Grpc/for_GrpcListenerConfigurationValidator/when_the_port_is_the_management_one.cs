// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Grpc.for_GrpcListenerConfigurationValidator;

/// <summary>
/// The management listener is private; serving the ingress-facing gRPC listener on its port would publish it.
/// </summary>
public class when_the_port_is_the_management_one : given.a_deployment_listening_on_the_public_port
{
    void Because() => Validate(new C.GrpcListener { Port = 9090 }, new C.Management { Port = 9090 });

    [Fact] void should_fail_validation() => _result.Failed.ShouldBeTrue();
    [Fact] void should_say_it_is_the_management_port() => _result.Failures.ShouldContain(_ => _.Contains("management", StringComparison.Ordinal));
}
