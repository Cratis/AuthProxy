// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Cratis.AuthProxy.Authentication.for_OidcClientAuthentication;

public class when_authenticating_a_token_request_with_an_assertion : Specification
{
    const string TokenEndpoint = "https://login.example.com/tenant/oauth2/v2.0/token";

    IOidcClientAssertions _assertions;
    C.OidcProvider _provider;
    OpenIdConnectOptions _options;
    DefaultHttpContext _httpContext;
    OpenIdConnectMessage _request;

    void Establish()
    {
        _assertions = Substitute.For<IOidcClientAssertions>();
        _assertions.Create(Arg.Any<string>(), Arg.Any<C.OidcProvider>(), Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns("signed-assertion");
        _provider = new()
        {
            Name = "Workforce",
            ClientId = "client-id",
            ClientCredential = new() { Source = C.OidcClientCredentialSource.ManagedIdentity }
        };
        _options = new() { Configuration = new OpenIdConnectConfiguration { TokenEndpoint = TokenEndpoint } };
        _httpContext = new() { RequestServices = new ServiceCollection().AddSingleton(_assertions).BuildServiceProvider() };
        _request = new() { ClientId = "client-id", ClientSecret = string.Empty, Code = "authorization-code" };
    }

    Task Because() => OidcClientAuthentication.Apply(_httpContext, "workforce", _provider, _options, _request);

    [Fact] void should_send_no_client_secret() => _request.Parameters.ContainsKey(OpenIdConnectParameterNames.ClientSecret).ShouldBeFalse();
    [Fact] void should_declare_a_jwt_assertion() => _request.ClientAssertionType.ShouldEqual("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    [Fact] void should_send_the_assertion() => _request.ClientAssertion.ShouldEqual("signed-assertion");
    [Fact] void should_address_the_assertion_to_the_token_endpoint() => _assertions.Received(1).Create("workforce", _provider, TokenEndpoint, Arg.Any<CancellationToken>());
}
