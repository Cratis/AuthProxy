// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningConfigurationValidator;

public class when_tenant_selection_signing_is_invalid : given.a_signing_configuration
{
    void Establish()
    {
        configuration.TenantResolutions =
        [
            new() { Strategy = C.TenantSourceIdentifierResolverType.Selection, Options = new Tenancy.SelectionOptions { TenantsEndpoint = "https://backend.test/tenants", ForwardedIdentity = new() } }
        ];
    }
    void Because() => Validate();
    [Fact] void should_reject_the_tenant_endpoint_settings() => result.Failed.ShouldBeTrue();
    [Fact] void should_identify_the_options_path() => result.FailureMessage.ShouldContain("TenantResolutions:0:Options:ForwardedIdentity");
}
