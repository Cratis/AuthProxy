// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Management.for_ManagementConfigurationValidator;

/// <summary>
/// Asking for a management listener without naming its port fails startup, pointing at the key.
/// <para>
/// The alternative is the worst kind of silence. No port means no listener, so every probe against it fails
/// to connect — and a failed connection is exactly what an unhealthy application looks like. The deployment
/// would be rolled back for a fault it does not have, over a value that never interpolated.
/// </para>
/// </summary>
public class when_the_section_names_no_port : given.a_deployment_listening_on_the_public_port
{
    void Because() => Validate(new C.Management());

    [Fact] void should_fail_validation() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_port_key() => _result.Failures.ShouldContain(_ => _.Contains("Cratis:AuthProxy:Management:Port", StringComparison.Ordinal));
    [Fact] void should_complain_about_nothing_else() => _result.Failures.Count().ShouldEqual(1);
}
