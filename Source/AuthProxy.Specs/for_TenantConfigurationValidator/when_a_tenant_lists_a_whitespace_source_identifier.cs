// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantConfigurationValidator;

public class when_a_tenant_lists_a_whitespace_source_identifier : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new TenantConfigurationValidator().Validate(null, new C.AuthProxy
    {
        Tenants = new C.Tenants { ["tenant-one"] = new C.Tenant { SourceIdentifiers = ["acme", " \t\u2003"] } }
    });

    [Fact] void should_reject_the_configuration() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_tenant_and_list() =>
        _result.Failures.ShouldContain($"{C.AuthProxy.SectionKey}:Tenants:tenant-one:SourceIdentifiers must not contain empty or whitespace-only entries.");
}
