// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using System.Text.Json;
using Cratis.AuthProxy.BearerRoutes.TokenExchange;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerTokenExchange.given;

internal sealed class ExchangeRequest
{
    static readonly long _expiration = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
    internal C.BearerTokenExchange Configuration { get; } = when_identity_answers.Configuration();
    internal ITenantResolver Resolver { get; } = Substitute.For<ITenantResolver>();
    internal ITenantVerifier Verifier { get; } = Substitute.For<ITenantVerifier>();
    internal ITokenExchangeClient Client { get; } = Substitute.For<ITokenExchangeClient>();
    internal TokenExchangeCache Cache { get; } = new(TimeProvider.System);
    internal DefaultHttpContext Context { get; } = new();
    internal C.BearerRoute Route { get; }
    internal ResolvedBearerRoute Resolved { get; }
    internal BearerTokenExchange Exchange { get; }

    internal ExchangeRequest()
    {
        Route = new() { Audiences = ["direct-mcp"], TokenExchange = Configuration, Issuers = [new() { Issuer = Configuration.ResultIssuer }] };
        Resolved = new("app", "https://backend.example", "/mcp", [new(Configuration.ResultIssuer, "https://identity.example/keys", ["JWT"], true)], Route, null, null);
        Exchange = new(Client, Cache, Resolver, Verifier);
        Context.Response.Body = new MemoryStream();
        Context.Request.Headers.Authorization = "Bearer " + Jwt();
        Targets(new TenantResolutionResult("tenant-a", C.TenantSourceIdentifierResolverType.Host));
        Verifier.VerifyAsync(Arg.Any<string>(), Arg.Any<string?>()).Returns(true);
        Client.Exchange(Arg.Any<C.BearerTokenExchange>(), Arg.Any<C.BearerTokenExchangeIssuer>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new TokenExchangeResult(TokenExchangeVerdict.Success, Jwt(Configuration.ResultIssuer, "direct-mcp"), 300));
    }

    internal void Targets(params TenantResolutionResult[] results) => Resolver.ResolveEach(Context).Returns(results);

    internal BearerTokenValidation Validation(string tenant = "tenant-a") => BearerTokenValidation.Success(
        new ClaimsPrincipal(new ClaimsIdentity([new Claim(Resolved.TenantClaimType, tenant)], "Bearer")), tenant) with { Issuer = Resolved.Issuers[0] };

    internal static string Jwt(string issuer = "https://external.example", string audience = "direct-mcp", string tenant = "tenant-a", string? idp = "https://external.example")
    {
        var claims = new Dictionary<string, object?> { ["iss"] = issuer, ["aud"] = audience, ["tid"] = tenant, ["exp"] = _expiration };
        if (idp is not null) claims["idp"] = idp;
        return Jwt(claims);
    }

    internal static string Jwt(Dictionary<string, object?> claims)
    {
        var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(claims))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return $"eyJhbGciOiJSUzI1NiJ9.{payload}.c2ln";
    }
}
