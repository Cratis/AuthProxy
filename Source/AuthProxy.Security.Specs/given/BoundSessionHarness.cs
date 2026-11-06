// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.given;

/// <summary>A real cookie-authenticated proxy with an explicit credential binding and shared keys.</summary>
/// <param name="resource">The deployment resource.</param>
/// <param name="environment">The deployment environment.</param>
/// <param name="keys">The shared key directory.</param>
public class BoundSessionHarness(string resource, string environment, string keys) : RequiredVerificationHarness
{
    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureServices(services => services.AddDataProtection().PersistKeysToFileSystem(new(keys)))
        .ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:CredentialBinding:Resource"] = resource,
            [$"{C.AuthProxy.SectionKey}:CredentialBinding:Environment"] = environment,
            [$"{C.AuthProxy.SectionKey}:DataProtectionKeysPath"] = keys,
        }));
    }
}
