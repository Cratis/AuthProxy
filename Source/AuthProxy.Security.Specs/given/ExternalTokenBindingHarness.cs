// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;

namespace Cratis.AuthProxy.Security.given;

/// <summary>A general JWT Bearer deployment with tenant binding, addressing and browser selection configured.</summary>
public class ExternalTokenBindingHarness : BearerRouteHarness
{
    /// <inheritdoc/>
    protected override bool UsesHeaderAuthentication => false;

    /// <inheritdoc/>
    protected override void ConfigureHost(IWebHostBuilder builder)
    {
        const string jwt = $"{C.Authentication.SectionKey}:JwtBearer";
        builder.UseSetting($"{jwt}:Authority", Issuer.Issuer)
            .UseSetting($"{jwt}:MetadataAddress", $"{Issuer.Issuer}.well-known/oauth-authorization-server")
            .UseSetting($"{jwt}:RequireHttpsMetadata", "false")
            .UseSetting($"{jwt}:Audience", Audience);
    }

    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        const string proxy = C.AuthProxy.SectionKey;
        settings[$"{C.Authentication.SectionKey}:ExternalTokenTenantBinding:Require"] = "true";

        // The general handler trusts the local issuer, not the separate bearer-route issuer.
        settings[$"{proxy}:Services:app:BearerRoutes:0:Issuers:0:Issuer"] = "https://bearer.example.test/";
        settings[$"{proxy}:Services:app:BearerRoutes:1:Issuers:0:Issuer"] = "https://bearer.example.test/";
        settings[$"{proxy}:Services:app:ResolveIdentityDetails"] = "false";
        settings[$"{proxy}:TenantResolutions:0:Options:TenantId"] = "tenant-a";
        settings[$"{proxy}:Tenants:tenant-a:Domains:0"] = "a.direct.example.test";
        settings[$"{proxy}:Tenants:tenant-b:Domains:0"] = "b.direct.example.test";
        settings[$"{proxy}:Tenants:tenant-a:SourceIdentifiers:0"] = "tenant-a";
        settings[$"{proxy}:Tenants:tenant-b:SourceIdentifiers:0"] = "tenant-b";
        settings[$"{proxy}:TenantResolutions:1:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Host);
        settings[$"{proxy}:TenantResolutions:2:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.SubHost);
        settings[$"{proxy}:TenantResolutions:2:Options:ParentHost"] = "sub.example.test";
        settings[$"{proxy}:TenantResolutions:3:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Route);
        settings[$"{proxy}:TenantResolutions:3:Options:Pattern"] = "/tenants/(?<sourceIdentifier>[^/]+)/";
        settings[$"{proxy}:TenantResolutions:4:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Selection);
        settings[$"{proxy}:TenantResolutions:4:Options:TenantsEndpoint"] = Origin.TenantsUrl;
    }
}
