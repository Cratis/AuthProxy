// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>A deployment with freshness rules but no forwarding-path rules.</summary>
public class FreshAuthenticationHarness : BearerRouteHarness
{
    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        const string service = $"{C.AuthProxy.SectionKey}:Services:app";
        settings[$"{service}:ResolveIdentityDetails"] = "false";
        string[] paths = ["/mcp/approve", "/v1/approve", "/approve", ResourceMetadataPath];
        for (var index = 0; index < paths.Length; index++)
        {
            var rule = $"{service}:FreshAuthentication:{index}";
            settings[$"{rule}:Path"] = paths[index];
            settings[$"{rule}:MaxAge"] = "00:05:00";
            if (paths[index] != ResourceMetadataPath)
            {
                settings[$"{rule}:Methods:0"] = "DELETE";
            }
        }
    }
}
