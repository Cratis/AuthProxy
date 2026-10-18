// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator;

/// <summary>
/// A tenant-selection endpoint on a configured service's origin borrows that service's audience, so a usable key and
/// a served endpoint need nothing more.
/// </summary>
public class when_the_configuration_is_usable : given.a_signing_deployment
{
    void Establish() => SelectTenantsFrom("http://reports-api:8080/api/tenants");

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
