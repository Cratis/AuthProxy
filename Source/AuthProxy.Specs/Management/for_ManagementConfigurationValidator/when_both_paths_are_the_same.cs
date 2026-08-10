// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management.for_ManagementConfigurationValidator;

/// <summary>
/// Pointing both answers at one path is refused, because only one of them can ever be reached — and the one
/// that is silently lost is readiness, whose whole purpose is to say no while liveness says yes.
/// </summary>
public class when_both_paths_are_the_same : given.a_deployment_listening_on_the_public_port
{
    void Because() => Validate(new C.Management { Port = 9110, LivePath = "/health", ReadyPath = "/health" });

    [Fact] void should_fail_validation() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_both_keys() => _result.Failures.ShouldContain(_ =>
        _.Contains("Cratis:AuthProxy:Management:LivePath", StringComparison.Ordinal) &&
        _.Contains("Cratis:AuthProxy:Management:ReadyPath", StringComparison.Ordinal));
}
