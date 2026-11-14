// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningConfigurationValidator;

public class when_multiple_services_collide : given.a_signing_configuration
{
    void Establish()
    {
        configuration.Services["other"] = new() { ForwardedIdentity = settings };
        configuration.Services["invalid"] = new() { ForwardedIdentity = new() };
        configuration.Services["last"] = new() { ForwardedIdentity = settings };
        configuration.TenantResolutions =
        [
            new()
            {
                Strategy = C.TenantSourceIdentifierResolverType.Selection,
                Options = new SelectionOptions { TenantsEndpoint = "https://other.test/tenants", ForwardedIdentity = settings }
            }
        ];
    }

    void Because() => Validate();

    [Fact]
    void should_report_service_failures_in_order_before_tenant_collisions() => result.Failures.ShouldEqual(
    [
        $"{C.AuthProxy.SectionKey}:Services:main:ForwardedIdentity; {C.AuthProxy.SectionKey}:Services:other:ForwardedIdentity",
        $"{C.AuthProxy.SectionKey}:Services:invalid:ForwardedIdentity:Audience must be 1–128 printable ASCII characters and not blank (R1).",
        $"{C.AuthProxy.SectionKey}:Services:main:ForwardedIdentity; {C.AuthProxy.SectionKey}:Services:last:ForwardedIdentity",
        $"{C.AuthProxy.SectionKey}:Services:other:ForwardedIdentity; {C.AuthProxy.SectionKey}:Services:last:ForwardedIdentity",
        $"{C.AuthProxy.SectionKey}:Services:main:ForwardedIdentity; {C.AuthProxy.SectionKey}:TenantResolutions:0:Options:ForwardedIdentity",
        $"{C.AuthProxy.SectionKey}:Services:other:ForwardedIdentity; {C.AuthProxy.SectionKey}:TenantResolutions:0:Options:ForwardedIdentity",
        $"{C.AuthProxy.SectionKey}:Services:last:ForwardedIdentity; {C.AuthProxy.SectionKey}:TenantResolutions:0:Options:ForwardedIdentity"
    ]);
}
