// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator;

/// <summary>
/// An endpoint on no configured service's origin has no audience to borrow. Rather than fail every tenant selection
/// at run time, startup asks for the audience to be stated.
/// </summary>
public class when_the_tenant_selection_endpoint_is_served_by_no_service : given.a_signing_deployment
{
    void Establish() => SelectTenantsFrom("http://tenants-api:8080/api/tenants");

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_ask_for_the_audience() => HasFailure("The tenant selection endpoint is not served by any configured service backend.").ShouldBeTrue();
}
