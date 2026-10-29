// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>A bearer deployment that exposes tools and metadata but hides administrative paths.</summary>
public class ForwardingPathBearerRouteHarness : BearerRouteHarness
{
    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        const string service = $"{C.AuthProxy.SectionKey}:Services:app";
        settings[$"{service}:ResolveIdentityDetails"] = "false";
        settings[$"{service}:ForwardedPaths:0:Path"] = RoutePrefix;
        settings[$"{service}:ForwardedPaths:1:Path"] = ResourceMetadataPath;
        settings[$"{service}:ForwardedPaths:1:Match"] = "Exact";
        settings[$"{service}:DeniedPaths:0:Path"] = "/mcp/admin";
    }
}
