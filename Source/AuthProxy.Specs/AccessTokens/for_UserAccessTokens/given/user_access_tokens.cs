// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens.given;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens.given;

/// <summary>
/// <see cref="UserAccessTokens"/> over a real token store, a stand-in token endpoint, and one OIDC provider
/// authenticated by client secret.
/// </summary>
public class user_access_tokens : a_user_token_store
{
    protected const string Scheme = "workforce";
    protected const string TokenEndpointUrl = "https://login.example.com/tenant/oauth2/v2.0/token";

    protected TokenEndpoint _endpoint;
    protected C.OidcProvider _provider;
    protected OpenIdConnectOptions _options;
    protected IOidcClientAssertions _assertions;
    protected UserAccessTokens _tokens;
    protected C.ServiceAccessToken _accessToken;
    protected string _sessionId;

    async Task Establish()
    {
        _endpoint = new TokenEndpoint();
        _provider = new() { Name = "Workforce", Authority = "https://login.example.com/tenant/v2.0", ClientId = "client-id", ClientSecret = "client-secret" };
        _options = new()
        {
            ClientId = "client-id",
            ClientSecret = "client-secret",
            Configuration = new OpenIdConnectConfiguration { TokenEndpoint = TokenEndpointUrl },
        };

        var oidcOptions = Substitute.For<IOptionsMonitor<OpenIdConnectOptions>>();
        oidcOptions.Get(Scheme).Returns(_ => _options);
        var authentication = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authentication.CurrentValue.Returns(_ => new C.Authentication { OidcProviders = [_provider] });
        _assertions = Substitute.For<IOidcClientAssertions>();
        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(UserAccessTokens.HttpClientName).Returns(_ => new HttpClient(_endpoint, disposeHandler: false));

        _tokens = new(_store, oidcOptions, authentication, _assertions, httpClientFactory, _time, NullLogger<UserAccessTokens>.Instance);
        _accessToken = new() { Scopes = ["api://reporting/access_as_user"] };
        _sessionId = await _store.Create(new(Scheme, "refresh-token"), CancellationToken.None);
    }

    protected Task<UserAccessTokenResult> Get() => _tokens.GetFor(_sessionId, _accessToken, CancellationToken.None);
}
