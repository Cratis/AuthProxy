// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantConfigurationValidator;

public class when_the_tenant_registry_is_valid : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new TenantConfigurationValidator().Validate(null, new C.AuthProxy
    {
        Tenants = new C.Tenants
        {
            ["tenant-one"] = new C.Tenant { SourceIdentifiers = ["acme", "tenant-acme"], Domains = ["acme.example.com"] },
            ["tenant-two"] = new C.Tenant()
        }
    });

    [Fact] void should_accept_the_configuration() => _result.Succeeded.ShouldBeTrue();
}
