// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Cratis.AuthProxy.for_EndSessionEndpointResolver;

public class when_resolving_for_an_oidc_provider_with_an_end_session_endpoint : Specification
{
    const string EndSessionEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/logout";

    EndSessionEndpointResolver _resolver;
    string? _result;

    void Establish()
    {
        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders = [new C.OidcProvider { Name = "Microsoft" }],
        });

        var options = new OpenIdConnectOptions
        {
            ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(
                new OpenIdConnectConfiguration { EndSessionEndpoint = EndSessionEndpoint }),
        };

        var oidcOptions = Substitute.For<IOptionsMonitor<OpenIdConnectOptions>>();
        oidcOptions.Get("microsoft").Returns(options);

        _resolver = new EndSessionEndpointResolver(authConfig, oidcOptions, Substitute.For<ILogger<EndSessionEndpointResolver>>());
    }

    async Task Because() => _result = await _resolver.Resolve("microsoft", CancellationToken.None);

    [Fact] void should_return_the_end_session_endpoint() => _result.ShouldEqual(EndSessionEndpoint);
}
