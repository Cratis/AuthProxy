// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Cratis.AuthProxy.for_EndSessionEndpointResolver;

public class when_resolving_for_an_oidc_provider_without_an_end_session_endpoint : Specification
{
    EndSessionEndpointResolver _resolver;
    string? _result;

    void Establish()
    {
        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders = [new C.OidcProvider { Name = "Contoso AD" }],
        });

        var options = new OpenIdConnectOptions
        {
            // The discovery document does not advertise an end-session endpoint.
            ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(new OpenIdConnectConfiguration()),
        };

        var oidcOptions = Substitute.For<IOptionsMonitor<OpenIdConnectOptions>>();
        oidcOptions.Get("contoso-ad").Returns(options);

        _resolver = new EndSessionEndpointResolver(authConfig, oidcOptions, Substitute.For<ILogger<EndSessionEndpointResolver>>());
    }

    async Task Because() => _result = await _resolver.Resolve("contoso-ad", CancellationToken.None);

    [Fact] void should_not_resolve_an_endpoint() => _result.ShouldBeNull();
}
