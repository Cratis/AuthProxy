// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Security.given;

/// <summary>A person belonging to two tenants, with host addressing before tenant selection.</summary>
public class TwoTenantPersonHarness : TenantSelectionHarness
{
    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Tenants:{TenantA}:Domains:0"] = "a.direct.example.test",
            [$"{C.AuthProxy.SectionKey}:Tenants:{TenantB}:Domains:0"] = "b.direct.example.test",
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Host),
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:1:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Selection),
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:1:Options:TenantsEndpoint"] = Origin.TenantsUrl,
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:1:Options:TenantIdPath"] = "id",
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:1:Options:TenantNamePath"] = "name",
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:1:Options:CacheTtl"] = "00:00:00",
        }));
    }
}
