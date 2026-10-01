// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A bearer route whose configured tenant claim and issuer include surrounding whitespace.
/// </summary>
public class PaddedBearerRouteHarness : BearerRouteHarness
{
    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        const string route = $"{C.AuthProxy.SectionKey}:Services:app:BearerRoutes:0";
        settings[$"{route}:TenantClaimType"] = " tenant ";
        settings[$"{route}:Issuers:0:Issuer"] = $" {Issuer.Issuer} ";
    }
}
