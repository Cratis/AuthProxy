// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware;

public abstract class given_a_published_vector_gate : given_a_credential_dispatching_gate
{
    protected static string[] Profiles(JsonElement vector)
    {
        var given = vector.GetProperty("given");
        return given.TryGetProperty("profiles", out var profiles)
            ? profiles.EnumerateArray().Select(_ => _.GetString()!).ToArray()
            : [given.GetProperty("profile").GetString()!];
    }

    protected static string ProfilePath(string profile) => profile switch
    {
        "pat-only" => PatOnlyPath,
        "oauth-only" => OAuthPath,
        "combined" => CombinedPath,
        _ => throw new ArgumentOutOfRangeException(nameof(profile)),
    };

    protected string AccessToken(JsonElement given)
    {
        using var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa) { KeyId = "published-vector" };
        var publicKey = new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = key.KeyId };
        var metadata = Substitute.For<IBearerIssuerMetadata>();
        metadata.GetSigningKeys(Arg.Any<ResolvedBearerIssuer>(), Arg.Any<CancellationToken>(), Arg.Any<bool>()).Returns([publicKey]);
        var validator = new BearerTokenValidator(metadata);
        Validator.Validate(Arg.Any<HttpRequest>(), Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>())
            .Returns(call => validator.Validate(call.Arg<HttpRequest>(), call.Arg<ResolvedBearerRoute>(), call.Arg<CancellationToken>()));

        var claims = new Dictionary<string, object>
        {
            ["sub"] = "synthetic-subject",
            ["tid"] = "tenant-a",
        };
        if (given.TryGetProperty("cnf", out var confirmation)) claims["cnf"] = confirmation.Clone();
        if (given.TryGetProperty("tokenScopes", out var scopes)) claims["scope"] = string.Join(' ', scopes.EnumerateArray().Select(_ => _.GetString()));

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://issuer.example.test",
            Audience = given.TryGetProperty("audience", out var audience) ? audience.GetString() : "direct-api",
            TokenType = "at+jwt",
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
            Claims = claims,
        });
    }

    protected void AssertRefused(HttpContext context, int status)
    {
        context.Response.StatusCode.ShouldEqual(status);
        context.Response.ContentType.ShouldEqual("application/json");
        context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
        context.Response.Headers.Location.ToString().ShouldBeEmpty();
        Forwarder.ReceivedCalls().ShouldBeEmpty();
        Next.ReceivedCalls().ShouldBeEmpty();
        context.User.Identity?.IsAuthenticated.ShouldNotEqual(true);
    }
}
