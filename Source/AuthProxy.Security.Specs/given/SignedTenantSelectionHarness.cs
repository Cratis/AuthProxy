// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// The deployment of <see cref="SecurityHarness"/>, choosing its tenant through a selection endpoint served by its own
/// backend, and signing what it forwards.
/// </summary>
/// <remarks>
/// The call to the tenant endpoint carries the caller's identity like a proxied request does, so it is signed too,
/// for the audience of the service whose backend serves the endpoint.
/// </remarks>
public class SignedTenantSelectionHarness : SecurityHarness
{
    /// <summary>The path of the tenant endpoint on the origin.</summary>
    public const string TenantsPath = "/api/tenants";

    /// <summary>Gets the signing key, whose public half a backend would pin.</summary>
    public SignedForwarding Key { get; } = SignedForwarding.Generate();

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        var settings = new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Selection),
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantsEndpoint"] = $"{Origin.BaseUrl.TrimEnd('/')}{TenantsPath}",
        };
        Key.AddTo(settings);

        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(settings));
    }
}
