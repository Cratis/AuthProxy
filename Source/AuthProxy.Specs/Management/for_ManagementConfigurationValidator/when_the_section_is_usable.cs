// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management.for_ManagementConfigurationValidator;

/// <summary>
/// The ordinary declaration — a free port, the default paths, the loopback default — passes.
/// </summary>
public class when_the_section_is_usable : given.a_deployment_listening_on_the_public_port
{
    void Because() => Validate(new C.Management { Port = 9110 });

    [Fact] void should_pass_validation() => _result.Succeeded.ShouldBeTrue();
}
