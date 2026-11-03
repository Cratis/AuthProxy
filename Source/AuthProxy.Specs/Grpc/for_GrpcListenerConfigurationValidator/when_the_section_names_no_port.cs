// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Grpc.for_GrpcListenerConfigurationValidator;

public class when_the_section_names_no_port : given.a_deployment_listening_on_the_public_port
{
    void Because() => Validate(new C.GrpcListener());

    [Fact] void should_fail_validation() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_port_key() => _result.Failures.ShouldContain(_ => _.Contains("Cratis:AuthProxy:GrpcListener:Port", StringComparison.Ordinal));
}
