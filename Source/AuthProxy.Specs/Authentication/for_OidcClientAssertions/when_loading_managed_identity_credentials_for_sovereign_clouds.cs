// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Identity.Abstractions;

namespace Cratis.AuthProxy.Authentication.for_OidcClientAssertions;

public class when_loading_managed_identity_credentials_for_sovereign_clouds : Specification
{
    readonly List<string?> _audiences = [];

    async Task Because()
    {
        foreach (var (authority, configuredAudience) in new[]
        {
            ("https://login.microsoftonline.us/tenant/v2.0", ""),
            ("https://login.chinacloudapi.cn/tenant/v2.0", ""),
            ("https://login.partner.microsoftonline.cn/tenant/v2.0", ""),
            ("https://login.usgovcloudapi.net/tenant/v2.0", ""),
            ("https://login.sovcloud-identity.fr/tenant/v2.0", ""),
            ("https://login.sovcloud-identity.de/tenant/v2.0", ""),
            ("https://login.sovcloud-identity.sg/tenant/v2.0", ""),
            ("https://login.microsoftonline.com/tenant/v2.0", ""),
            ("https://login.example.com/tenant/v2.0", ""),
            ("https://login.microsoftonline.us/tenant/v2.0", "api://custom-exchange")
        })
        {
            var loader = Substitute.For<ICredentialsLoader>();
            loader.LoadCredentialsIfNeededAsync(Arg.Any<CredentialDescription>(), Arg.Any<CredentialSourceLoaderParameters?>())
                .Returns(call =>
                {
                    // The audience is already resolved before the loader's eager token acquisition, and stays
                    // resolved on later loads/refreshes even when the loader supplies no assertion request options.
                    _audiences.Add(call.Arg<CredentialDescription>().TokenExchangeUrl);
                    return Task.CompletedTask;
                });
            var provider = new C.OidcProvider
            {
                Name = "Workforce",
                Authority = authority,
                ClientId = "client-id",
                ClientCredential = new()
                {
                    Source = C.OidcClientCredentialSource.ManagedIdentity,
                    TokenExchangeAudience = configuredAudience
                }
            };
            var assertions = new OidcClientAssertions(loader, TimeProvider.System, NullLogger<OidcClientAssertions>.Instance);
            await Catch.Exception(() => assertions.Create("workforce", provider, "https://login.example.com/token", CancellationToken.None));
            await Catch.Exception(() => assertions.Create("workforce", provider, "https://login.example.com/token", CancellationToken.None));
        }
    }

    [Fact]
    void should_resolve_the_audience_before_initial_and_subsequent_loads() => _audiences.ShouldEqual(new[]
    {
        "api://AzureADTokenExchangeUSGov", "api://AzureADTokenExchangeUSGov",
        "api://AzureADTokenExchangeChina", "api://AzureADTokenExchangeChina",
        "api://AzureADTokenExchangeChina", "api://AzureADTokenExchangeChina",
        "api://AzureADTokenExchangeUSGov", "api://AzureADTokenExchangeUSGov",
        "api://AzureADTokenExchangeFrance", "api://AzureADTokenExchangeFrance",
        "api://AzureADTokenExchangeGermany", "api://AzureADTokenExchangeGermany",
        "api://AzureADTokenExchangeGovSG", "api://AzureADTokenExchangeGovSG",
        "api://AzureADTokenExchange", "api://AzureADTokenExchange",
        "api://AzureADTokenExchange", "api://AzureADTokenExchange",
        "api://custom-exchange", "api://custom-exchange"
    });
}
