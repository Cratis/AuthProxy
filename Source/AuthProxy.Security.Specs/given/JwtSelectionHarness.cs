// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Security.given;

/// <summary>A session deployment with local JWT validation and a controlled clock.</summary>
public class JwtSelectionHarness : CredentialSelectionHarness
{
    const string Issuer = "https://jwt.example.test";
    const string Audience = "scheme-specs";
    readonly SymmetricSecurityKey _signingKey = new(RandomNumberGenerator.GetBytes(32));

    /// <summary>Creates a signed JWT for the deployment.</summary>
    /// <returns>The signed token.</returns>
    public string JwtToken() => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
    {
        Issuer = Issuer,
        Audience = Audience,
        Subject = new ClaimsIdentity([new Claim("sub", "jwt-client"), new Claim(TenantClaim, TenantSourceIdentifier)]),
        IssuedAt = Clock.GetUtcNow().UtcDateTime,
        NotBefore = Clock.GetUtcNow().UtcDateTime,
        Expires = Clock.GetUtcNow().AddHours(1).UtcDateTime,
        SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256),
    });

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting($"{C.Authentication.SectionKey}:JwtBearer:Audience", Audience)
            .ConfigureTestServices(services => services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                options.Configuration = new OpenIdConnectConfiguration { Issuer = Issuer };
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = Issuer,
                    ValidAudience = Audience,
                    IssuerSigningKey = _signingKey,
                    ClockSkew = TimeSpan.Zero,
                    LifetimeValidator = (notBefore, expires, _, _) => notBefore <= Clock.GetUtcNow().UtcDateTime && expires > Clock.GetUtcNow().UtcDateTime,
                };
            }));
    }
}
