// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningReport;

public class when_signed_and_legacy_flows_coexist : Specification
{
    const string Secret = "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=";
    C.AuthProxy _configuration;
    IReadOnlyList<ForwardedIdentityFlowStatus> _rows;

    void Establish()
    {
        _configuration = new()
        {
            Services = new Dictionary<string, C.Service>
            {
                ["app"] = new()
                {
                    Backend = new() { BaseUrl = "https://backend.example" },
                    ForwardedIdentity = new() { Audience = "app-audience", KeyId = "app-key", SecretBase64 = Secret },
                    BearerRoutes = [new() { PathPrefix = "/mcp" }]
                },
                ["legacy"] = new() { Backend = new() { BaseUrl = "https://legacy.example" } }
            },
            TenantResolutions = [new() { Strategy = C.TenantSourceIdentifierResolverType.Selection, Options = new Tenancy.SelectionOptions { TenantsEndpoint = "https://tenants.example/list" } }]
        };
    }

    void Because() => _rows = ForwardedIdentitySigningReport.For(_configuration);

    [Fact] void should_list_the_proxied_signed_flow() => _rows.Single(row => row.Flow == ForwardedIdentityFlow.ProxiedRequest && row.ServiceName == "app").IsSigned.ShouldBeTrue();
    [Fact] void should_list_the_signed_bearer_flow() => _rows.Single(row => row.Flow == ForwardedIdentityFlow.BearerRoute).IsSigned.ShouldBeTrue();
    [Fact] void should_list_signed_identity_details() => _rows.Single(row => row.Flow == ForwardedIdentityFlow.IdentityDetails && row.ServiceName == "app").IsSigned.ShouldBeTrue();
    [Fact] void should_list_unsigned_legacy_proxying() => _rows.Single(row => row.Flow == ForwardedIdentityFlow.ProxiedRequest && row.ServiceName == "legacy").IsSigned.ShouldBeFalse();
    [Fact] void should_list_unsigned_tenant_calls() => _rows.Single(row => row.Flow == ForwardedIdentityFlow.TenantList).IsSigned.ShouldBeFalse();
    [Fact] void should_not_include_secret_material() => string.Join(';', _rows).ShouldNotContain(Secret);
    [Fact] void should_not_report_an_unconfigured_bearer_route() => _rows.Any(row => row.Flow == ForwardedIdentityFlow.BearerRoute && row.ServiceName == "legacy").ShouldBeFalse();
}
