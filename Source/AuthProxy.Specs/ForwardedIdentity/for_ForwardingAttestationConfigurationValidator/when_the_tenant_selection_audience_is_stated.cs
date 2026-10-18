// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator;

/// <summary>
/// A stated audience lets the tenant-selection call be signed even when no configured service serves the endpoint.
/// </summary>
public class when_the_tenant_selection_audience_is_stated : given.a_signing_deployment
{
    void Establish() => SelectTenantsFrom("http://tenants-api:8080/api/tenants", "tenants-api");

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
