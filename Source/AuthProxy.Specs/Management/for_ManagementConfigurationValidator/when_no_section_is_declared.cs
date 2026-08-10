// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management.for_ManagementConfigurationValidator;

/// <summary>
/// The validator is registered unconditionally, so it judges every deployment — including the overwhelming
/// majority that never asked for a management listener. Not asking for one is not a misconfiguration.
/// </summary>
public class when_no_section_is_declared : given.a_deployment_listening_on_the_public_port
{
    void Because() => Validate(null);

    [Fact] void should_pass_validation() => _result.Succeeded.ShouldBeTrue();
}
