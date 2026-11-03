// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Grpc.for_GrpcListenerConfigurationValidator;

/// <summary>
/// The public listener speaks HTTP/1.1 and HTTP/2 with negotiation, which plain-text gRPC cannot use, so sharing it is
/// refused rather than leaving gRPC calls failing at the ingress.
/// </summary>
public class when_the_port_is_the_public_one : given.a_deployment_listening_on_the_public_port
{
    void Because() => Validate(new C.GrpcListener { Port = PublicPort });

    [Fact] void should_fail_validation() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_offending_value() => _result.Failures.ShouldContain(_ => _.Contains("8080", StringComparison.Ordinal));
}
