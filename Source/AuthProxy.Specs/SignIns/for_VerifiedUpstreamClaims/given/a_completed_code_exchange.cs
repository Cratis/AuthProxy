// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns.for_VerifiedUpstreamClaims.given;

/// <summary>
/// The moment the OpenID Connect handler has validated the identity token of an authorization-code exchange: the
/// token endpoint response is in hand, and the sign-in is about to capture what it verified.
/// </summary>
public class a_completed_code_exchange : Specification
{
    protected const string Scheme = "oidc-upstream";
    protected const string Issuer = "https://idp.example.com";
    protected const string ClientId = "authproxy-client";

    protected static readonly RsaSecurityKey ProviderKey = new(RSA.Create(2048)) { KeyId = "provider" };
    protected static readonly RsaSecurityKey OtherKey = new(RSA.Create(2048)) { KeyId = "other" };

    protected DefaultHttpContext _httpContext;
    protected TokenValidatedContext _context;

    protected virtual SecurityKey AccessTokenKey => ProviderKey;

    protected virtual string AccessTokenSubject => "acct-1";

    protected virtual bool ReturnsAccessToken => true;

    protected virtual bool IncludesClaims => true;

    void Establish()
    {
        var configuration = new C.AuthProxy { SignIn = new C.SignIn { IncludeVerifiedUpstreamClaims = IncludesClaims } };
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(configuration);

        _httpContext = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection()
                .AddSingleton(monitor)
                .AddSingleton(Substitute.For<ILoggerFactory>())
                .BuildServiceProvider(),
        };

        var options = new OpenIdConnectOptions { ClientId = ClientId };
        var providerConfiguration = new OpenIdConnectConfiguration { Issuer = Issuer };
        providerConfiguration.SigningKeys.Add(ProviderKey);
        options.Configuration = providerConfiguration;

        // The handler hands the validated identity token to its events as a JwtSecurityToken.
        var idToken = new JwtSecurityToken(new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Claims = new Dictionary<string, object> { ["sub"] = "acct-1", ["auth_time"] = 1700000000L },
        }));

        _context = new TokenValidatedContext(
            _httpContext,
            new AuthenticationScheme(Scheme, null, typeof(OpenIdConnectHandler)),
            options,
            new ClaimsPrincipal(new ClaimsIdentity()),
            new AuthenticationProperties())
        {
            SecurityToken = idToken,
            TokenEndpointResponse = new OpenIdConnectMessage
            {
                AccessToken = ReturnsAccessToken ? CreateAccessToken() : null,
            },
        };
    }

    string CreateAccessToken() => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
    {
        Issuer = Issuer,
        Audience = ClientId,
        Expires = DateTime.UtcNow.AddMinutes(10),
        TokenType = "at+jwt",
        SigningCredentials = new SigningCredentials(AccessTokenKey, SecurityAlgorithms.RsaSha256),
        Claims = new Dictionary<string, object> { ["sub"] = AccessTokenSubject, ["github_id"] = "777" },
    });
}
