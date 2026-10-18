// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator;

/// <summary>
/// Two services on the same backend with different audiences leave no way to tell which one serves the endpoint,
/// so startup asks for the audience to be stated instead of picking one.
/// </summary>
public class when_services_sharing_the_tenant_selection_endpoint_disagree : given.a_signing_deployment
{
    void Establish()
    {
        _configuration.Services["catalog"] = new C.Service
        {
            Backend = new C.ServiceEndpoint { BaseUrl = "http://reports-api:8080/" },
            ForwardingAudience = "catalog-api",
        };
        SelectTenantsFrom("http://reports-api:8080/api/tenants");
    }

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_report_the_ambiguity() => HasFailure("served by several services with different forwarding audiences").ShouldBeTrue();
}
