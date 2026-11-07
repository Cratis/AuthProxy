// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>A bearer deployment addressed through its tenant host.</summary>
public class AddressedBearerRouteHarness : BearerRouteHarness
{
    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        settings[$"{C.AuthProxy.SectionKey}:CredentialBinding:Environment"] = "staging";
        settings[$"{C.AuthProxy.SectionKey}:Services:app:BearerRoutes:0:EnvironmentClaimType"] = "env";
        settings[$"{C.AuthProxy.SectionKey}:Tenants:tenant-a:Domains:0"] = "a.direct.example.test";
        settings[$"{C.AuthProxy.SectionKey}:Tenants:tenant-b:Domains:0"] = "b.direct.example.test";
        settings[$"{C.AuthProxy.SectionKey}:TenantResolutions:1:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Host);
    }
}
