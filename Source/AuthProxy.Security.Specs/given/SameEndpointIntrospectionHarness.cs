// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Two routes asking the same introspection endpoint as the same client, with different cache windows.
/// </summary>
public class SameEndpointIntrospectionHarness : IntrospectionHarness
{
    /// <inheritdoc/>
    protected override void AddSettings(IDictionary<string, string?> settings)
    {
        base.AddSettings(settings);
        const string cachedIssuer = $"{C.AuthProxy.SectionKey}:Services:app:BearerRoutes:1:Issuers:0:Introspection";
        settings[$"{cachedIssuer}:{nameof(C.BearerIssuerIntrospection.Endpoint)}"] = $"{Endpoint.BaseUrl}{StubIntrospectionEndpoint.Path}";
    }
}
