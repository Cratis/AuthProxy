// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Scenarios.when_anonymous_paths_are_configured;

/// <summary>
/// The same host with a second service declaring a prefix the first service already declares — the
/// copy-paste a multi-service deployment makes when two services expose the same public surface.
/// </summary>
public class SharedPrefixAuthProxyFactory : AuthProxyFactory
{
    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        builder.ConfigureAppConfiguration((_, config) =>
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Services:other:Backend:BaseUrl"] = "http://other-backend.test/",
                [$"{C.AuthProxy.SectionKey}:Services:other:Frontend:BaseUrl"] = "http://other-frontend.test/",
                [$"{C.AuthProxy.SectionKey}:Services:other:AnonymousPaths:0"] = AnonymousFrontendPath,
            }));
    }
}
