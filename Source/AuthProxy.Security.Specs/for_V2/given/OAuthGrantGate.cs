// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Authorization;
using Cratis.AuthProxy.BearerRoutes;
using Cratis.AuthProxy.BearerRoutes.Introspection;
using Cratis.AuthProxy.Tenancy;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;

namespace Cratis.AuthProxy.Security.for_V2.given;

sealed class OAuthGrantGate : IDisposable
{
    internal const string Realm = "https://realm.example.test";
    internal const string CredentialId = "22222222-2222-4222-8222-222222222222";
    internal const string Subject = "11111111-1111-4111-8111-111111111111";
    readonly RSA _key = RSA.Create(2048);
    readonly IOptionsMonitor<C.AuthProxy> _monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
    readonly IBearerIssuerMetadata _metadata = Substitute.For<IBearerIssuerMetadata>();
    internal IBearerRouteForwarder Forwarder { get; } = Substitute.For<IBearerRouteForwarder>();
    internal IBearerTokenIntrospector Introspector { get; } = Substitute.For<IBearerTokenIntrospector>();
    internal DefaultHttpContext Http { get; } = new();
    internal C.BearerIssuer Issuer { get; } = new() { Issuer = Realm, Introspection = new() { Endpoint = Realm + "/introspect", ClientId = "test-client", ClientSecret = "synthetic-test-secret" } };
    internal C.BearerRoute Route { get; } = new() { PathPrefix = "/api", Audiences = ["backend"], ForwardAuthorizationHeader = true };
    internal C.Service Service { get; }
    internal BearerForwardedIdentity? Forwarded { get; private set; }

    internal OAuthGrantGate()
    {
        Route.Issuers.Add(Issuer);
        Service = new() { Backend = new() { BaseUrl = "https://backend.example.test" }, PathPrefix = "/api", BearerRoutes = [Route], ForwardedIdentity = new() { Version = "v2" } };
        _monitor.CurrentValue.Returns(new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["app"] = Service } });
        _metadata.GetSigningKeys(Arg.Any<ResolvedBearerIssuer>(), Arg.Any<CancellationToken>(), Arg.Any<bool>()).Returns(Task.FromResult<IReadOnlyCollection<SecurityKey>?>([new RsaSecurityKey(_key) { KeyId = "test-key" }]));
        Introspector.IntrospectWithEvidence(Arg.Any<string>(), Arg.Any<BearerTokenValidation>(), Arg.Any<ResolvedBearerIssuer>(), Arg.Any<CancellationToken>()).Returns(new IntrospectionResult(IntrospectionVerdict.Active, new(CredentialId, "7"), DateTimeOffset.UtcNow.AddMinutes(1)) { ValidUntil = DateTimeOffset.UtcNow.AddSeconds(30) });
        Forwarder.Forward(Arg.Any<HttpContext>(), Arg.Any<ResolvedBearerRoute>(), Arg.Any<BearerForwardedIdentity?>()).Returns(call =>
        {
            Forwarded = call.ArgAt<BearerForwardedIdentity?>(2);
            return Task.CompletedTask;
        });
        Http.Request.Scheme = "https";
        Http.Request.Path = "/api/resource";
    }

    internal string Mint(Action<Dictionary<string, object>>? alter = null, Action<SecurityTokenDescriptor>? configure = null)
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = Subject,
            ["tid"] = "tenant-a",
            ["scope"] = "read",
            ["idp"] = "local",
            ["auth_time"] = DateTimeOffset.UtcNow.AddMinutes(-2).ToUnixTimeSeconds(),
            ["acr"] = "basic",
            ["amr"] = new[] { "pwd" },
            ["jti"] = "not-the-credential-record",
            ["cid"] = CredentialId
        };
        alter?.Invoke(claims);
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = Realm,
            Audience = "backend",
            Claims = claims,
            Expires = DateTime.UtcNow.AddMinutes(2),
            IssuedAt = DateTime.UtcNow.AddMinutes(-1),
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            TokenType = "at+jwt",
            SigningCredentials = new(new RsaSecurityKey(_key) { KeyId = "test-key" }, SecurityAlgorithms.RsaSha256)
        };
        configure?.Invoke(descriptor);
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    internal Task Invoke(string token)
    {
        Http.Request.Headers.Authorization = "Bearer " + token;
        var access = Substitute.For<IAccessPolicy>();
        access.Evaluate(Arg.Any<System.Security.Claims.ClaimsPrincipal>(), Arg.Any<C.AuthProxy>(), Arg.Any<string>(), Arg.Any<C.BearerRoute>()).Returns(AccessDecision.Granted);
        var tenants = Substitute.For<ITenantVerifier>();
        tenants.VerifyAsync(Arg.Any<string>()).Returns(true);
        var gate = new BearerRouteMiddleware(
            _ => throw new InvalidOperationException("The bearer route must own this request."),
            _monitor,
            new BearerTokenValidator(_metadata),
            Introspector,
            access,
            tenants,
            Substitute.For<ITenantResolver>(),
            Forwarder,
            new ClientCredentialsTokenProtector(new EphemeralDataProtectionProvider()),
            NullLogger<BearerRouteMiddleware>.Instance);
        return gate.InvokeAsync(Http);
    }

    public void Dispose() => _key.Dispose();
}
