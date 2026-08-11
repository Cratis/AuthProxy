// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management.for_ManagementConfigurationValidator;

/// <summary>
/// A path that does not start with <c>/</c> matches no request, so the listener would open, accept the
/// probe's connection, and answer it the same not-found it answers everything else. That reads as an
/// application fault rather than as a typo in a path.
/// </summary>
public class when_a_path_is_not_rooted : given.a_deployment_listening_on_the_public_port
{
    void Because() => Validate(new C.Management { Port = 9110, LivePath = "health/live", ReadyPath = "health/ready" });

    [Fact] void should_fail_validation() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_liveness_key() => _result.Failures.ShouldContain(_ => _.Contains("Cratis:AuthProxy:Management:LivePath", StringComparison.Ordinal));
    [Fact] void should_name_the_readiness_key() => _result.Failures.ShouldContain(_ => _.Contains("Cratis:AuthProxy:Management:ReadyPath", StringComparison.Ordinal));
    [Fact] void should_name_the_offending_value() => _result.Failures.ShouldContain(_ => _.Contains("'health/live'", StringComparison.Ordinal));
}
