// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Security.given;

/// <summary>A deployment whose session cookie is shared across its configured domain.</summary>
public class SharedSessionSelectionHarness : CredentialSelectionHarness
{
    /// <summary>The configured session domain.</summary>
    public const string SessionDomain = ".example.test";

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Session:CookieDomain"] = SessionDomain,
        }));
    }
}
