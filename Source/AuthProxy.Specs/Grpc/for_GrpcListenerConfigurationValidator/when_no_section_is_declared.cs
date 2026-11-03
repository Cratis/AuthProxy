// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Grpc.for_GrpcListenerConfigurationValidator;

public class when_no_section_is_declared : given.a_deployment_listening_on_the_public_port
{
    void Because() => Validate(null);

    [Fact] void should_pass_validation() => _result.Succeeded.ShouldBeTrue();
}
