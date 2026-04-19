// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

/// <summary>Extends <see cref="AuthProxyFactory"/> with two OIDC providers so the provider-selection page is served.</summary>
public class MultipleProvidersAuthProxyFactory : AuthProxyFactory
{
    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Provider One",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.example.com/one",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-one",
                [$"{C.Authentication.SectionKey}:OidcProviders:1:Name"] = "Provider Two",
                [$"{C.Authentication.SectionKey}:OidcProviders:1:Authority"] = "https://login.example.com/two",
                [$"{C.Authentication.SectionKey}:OidcProviders:1:ClientId"] = "client-two",
            });
        });
    }
}
