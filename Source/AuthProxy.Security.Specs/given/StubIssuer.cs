// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A stand-in authorization server on loopback: publishes RFC 8414 metadata and a JWKS for a local RSA key,
/// and signs access tokens shaped like the ones Cratis Identity issues.
/// </summary>
/// <remarks>
/// It listens on a real socket because AuthProxy reads the metadata and keys over HTTP exactly as it would from
/// a deployed issuer; nothing about discovery is substituted. Plain HTTP is accepted only because the issuer is
/// on a loopback host.
/// </remarks>
public sealed class StubIssuer : IAsyncDisposable
{
    /// <summary>The key id the published key carries.</summary>
    public const string KeyId = "stub-issuer-key";

    readonly WebApplication _app;
    readonly RSA _rsa;
    string _keyId = KeyId;
    int _metadataRequests;

    StubIssuer(WebApplication app, RSA rsa, string issuer)
    {
        _app = app;
        _rsa = rsa;
        Issuer = issuer;
    }

    /// <summary>
    /// Gets the issuer identifier, with the trailing slash Cratis Identity uses.
    /// </summary>
    public string Issuer { get; }

    /// <summary>
    /// Gets the number of discovery requests received.
    /// </summary>
    public int MetadataRequests => Volatile.Read(ref _metadataRequests);

    /// <summary>
    /// Gets or sets whether discovery returns an unavailable document.
    /// </summary>
    public bool MetadataUnavailable { get; set; }

    /// <summary>
    /// Starts a new stub issuer.
    /// </summary>
    /// <returns>The started issuer.</returns>
    public static async Task<StubIssuer> Start()
    {
        var rsa = RSA.Create(2048);
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        string? issuer = null;
        StubIssuer? stub = null;

        app.MapGet("/.well-known/oauth-authorization-server", () =>
        {
            Interlocked.Increment(ref stub!._metadataRequests);
            return stub.MetadataUnavailable
                ? Results.NotFound()
                : Results.Json(new Dictionary<string, object>
                {
                    ["issuer"] = issuer!,
                    ["jwks_uri"] = $"{issuer}.well-known/jwks",
                    ["authorization_endpoint"] = $"{issuer}connect/authorize",
                    ["token_endpoint"] = $"{issuer}connect/token",
                });
        });

        app.MapGet("/.well-known/jwks", () =>
        {
            var parameters = rsa.ExportParameters(includePrivateParameters: false);
            return Results.Json(new
            {
                keys = new[]
                {
                    new Dictionary<string, string>
                    {
                        ["kty"] = "RSA",
                        ["use"] = "sig",
                        ["alg"] = SecurityAlgorithms.RsaSha256,
                        ["kid"] = stub!._keyId,
                        ["n"] = Base64UrlEncoder.Encode(parameters.Modulus),
                        ["e"] = Base64UrlEncoder.Encode(parameters.Exponent),
                    },
                },
            });
        });

        await app.StartAsync();

        var address = app.Services.GetRequiredService<IServer>().Features
            .Get<IServerAddressesFeature>()!
            .Addresses
            .First();
        issuer = $"{address.TrimEnd('/')}/";

        return stub = new StubIssuer(app, rsa, issuer);
    }

    /// <summary>
    /// Signs an access token with the published key.
    /// </summary>
    /// <param name="claims">The claims, which replace the defaults of <see cref="DefaultClaims"/> they name.</param>
    /// <param name="audience">The audience.</param>
    /// <param name="expires">When the token expires. Defaults to fifteen minutes from now.</param>
    /// <param name="issuer">The issuer to name. Defaults to this issuer.</param>
    /// <param name="without">Default claims to leave out.</param>
    /// <returns>The signed token.</returns>
    public string Token(
        IDictionary<string, object>? claims = null,
        string audience = BearerRouteHarness.Audience,
        DateTime? expires = null,
        string? issuer = null,
        params string[] without) =>
        Sign(new RsaSecurityKey(_rsa) { KeyId = _keyId }, claims, audience, expires, issuer, without);

    /// <summary>
    /// Replaces the published signing key and its identifier.
    /// </summary>
    public void RotateKey()
    {
        using var replacement = RSA.Create(2048);
        _rsa.ImportParameters(replacement.ExportParameters(includePrivateParameters: true));
        _keyId = Guid.NewGuid().ToString("N");
    }

    /// <summary>
    /// Signs an access token with the published key, then lets the caller reshape it before it is written.
    /// </summary>
    /// <param name="shape">Changes the descriptor: the type, the signing or encrypting credentials, the lifetime.</param>
    /// <param name="setDefaultTimes">Whether the handler fills in lifetimes the descriptor leaves unset.</param>
    /// <returns>The token.</returns>
    public string TokenShaped(Action<SecurityTokenDescriptor> shape, bool setDefaultTimes = true) =>
        Sign(new RsaSecurityKey(_rsa) { KeyId = _keyId }, null, BearerRouteHarness.Audience, null, null, [], shape, setDefaultTimes);

    /// <summary>
    /// Signs a token with HMAC, keyed with this issuer's published public key — the algorithm-confusion attack on
    /// a validator that lets the token pick its algorithm.
    /// </summary>
    /// <returns>The token.</returns>
    public string TokenSignedWithThePublicKeyAsASecret()
    {
        var publicKey = _rsa.ExportSubjectPublicKeyInfo();
        return Sign(new SymmetricSecurityKey(publicKey) { KeyId = KeyId }, null, BearerRouteHarness.Audience, null, null, [], algorithm: SecurityAlgorithms.HmacSha256);
    }

    /// <summary>
    /// Signs an access token with a key this issuer does not publish, but names the published key id.
    /// </summary>
    /// <returns>The token.</returns>
    public string TokenSignedByAnotherKey()
    {
        using var other = RSA.Create(2048);
        return Sign(new RsaSecurityKey(other) { KeyId = KeyId }, null, BearerRouteHarness.Audience, null, null, []);
    }

    /// <summary>
    /// Builds an unsigned token (<c language="text">alg: none</c>) carrying otherwise valid claims.
    /// </summary>
    /// <returns>The token.</returns>
    public string UnsignedToken()
    {
        var now = DateTimeOffset.UtcNow;
        var header = Base64UrlEncoder.Encode(/*lang=json,strict*/ """{"alg":"none","typ":"at+jwt"}""");
        var payload = new Dictionary<string, object>(DefaultClaims())
        {
            ["iss"] = Issuer,
            ["aud"] = BearerRouteHarness.Audience,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["nbf"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddMinutes(15).ToUnixTimeSeconds(),
        };

        return $"{header}.{Base64UrlEncoder.Encode(System.Text.Json.JsonSerializer.Serialize(payload))}.";
    }

    /// <summary>
    /// Gets the claims a Cratis Identity access token carries.
    /// </summary>
    /// <returns>The claims.</returns>
    public static Dictionary<string, object> DefaultClaims() => new()
    {
        ["sub"] = BearerRouteHarness.AccountId,
        ["tid"] = BearerRouteHarness.TenantId,
        ["scope"] = "direct:read direct:work",
        ["azp"] = BearerRouteHarness.ClientId,
        ["client_id"] = BearerRouteHarness.ClientId,
        ["github_id"] = BearerRouteHarness.GitHubId,
        ["github_login"] = BearerRouteHarness.GitHubLogin,
        ["name"] = "Einar Ingebrigtsen",
        ["preferred_username"] = BearerRouteHarness.GitHubLogin,
        ["jti"] = Guid.NewGuid().ToString("N"),
    };

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        _rsa.Dispose();
    }

    string Sign(
        SecurityKey key,
        IDictionary<string, object>? claims,
        string audience,
        DateTime? expires,
        string? issuer,
        string[] without,
        Action<SecurityTokenDescriptor>? shape = null,
        bool setDefaultTimes = true,
        string algorithm = SecurityAlgorithms.RsaSha256)
    {
        var merged = DefaultClaims();
        foreach (var type in without)
        {
            merged.Remove(type);
        }

        foreach (var (type, value) in claims ?? new Dictionary<string, object>())
        {
            merged[type] = value;
        }

        var expiry = expires ?? DateTime.UtcNow.AddMinutes(15);
        var issuedAt = expiry.AddMinutes(-15);

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer ?? Issuer,
            Audience = audience,
            Claims = merged,
            IssuedAt = issuedAt,
            NotBefore = issuedAt,
            Expires = expiry,
            TokenType = "at+jwt",
            SigningCredentials = new SigningCredentials(key, algorithm),
        };
        shape?.Invoke(descriptor);

        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = setDefaultTimes }.CreateToken(descriptor);
    }
}
