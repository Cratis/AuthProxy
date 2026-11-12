// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Security.for_SessionLifetime.given;

public class a_provider_session(string lifetime = "01:00:00") : CredentialSelectionHarness
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Session:Lifetime"] = lifetime,
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Session:SlidingExpiration"] = "true"
        }));
    }
}
