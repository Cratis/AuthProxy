// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenSessions.given;

/// <summary>
/// An OIDC sign-in whose token response has just arrived, in a deployment where one service forwards user tokens.
/// </summary>
public class a_sign_in_redeeming_its_code : Specification
{
    protected C.AuthProxy _config;
    protected IUserTokenStore _store;
    protected AuthenticationProperties _properties;
    protected IAuthenticationService _authentication;
    protected TokenResponseReceivedContext _context;

    void Establish()
    {
        _config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["reporting"] = new() { AccessToken = new() { Scopes = ["api://reporting/.default"] } },
            },
        };
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(_ => _config);

        _store = Substitute.For<IUserTokenStore>();
        _store.Create(Arg.Any<UserTokenSession>(), Arg.Any<CancellationToken>()).Returns("session-id");

        _authentication = Substitute.For<IAuthenticationService>();
        var services = new ServiceCollection()
            .AddLogging()
            .AddSingleton(monitor)
            .AddSingleton(_store)
            .AddSingleton(_authentication)
            .BuildServiceProvider();

        _properties = new AuthenticationProperties();
        _context = new TokenResponseReceivedContext(
            new DefaultHttpContext { RequestServices = services },
            new AuthenticationScheme("workforce", null, typeof(OpenIdConnectHandler)),
            new OpenIdConnectOptions(),
            new ClaimsPrincipal(),
            _properties)
        {
            TokenEndpointResponse = new OpenIdConnectMessage { AccessToken = "sign-in-access-token", IdToken = "id-token", RefreshToken = "refresh-token" },
        };
    }
}
