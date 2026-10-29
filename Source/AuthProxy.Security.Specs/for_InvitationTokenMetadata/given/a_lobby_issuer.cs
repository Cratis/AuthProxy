// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using Cratis.AuthProxy.Invites;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Security.for_InvitationTokenMetadata.given;

public class a_lobby_issuer : IAsyncLifetime
{
    readonly RSA _rsa = RSA.Create(2048);
    WebApplication _lobby;
    ServiceProvider _services;
    int _sinkRequests;
    int _metadataRequests;
    int _keyRequests;

    protected string BaseUrl { get; private set; } = string.Empty;
    protected InviteTokenValidationResult Result { get; private set; }
    protected int SinkRequests => Volatile.Read(ref _sinkRequests);
    protected int MetadataRequests => Volatile.Read(ref _metadataRequests);
    protected int KeyRequests => Volatile.Read(ref _keyRequests);
    protected virtual bool RedirectMetadata => false;
    protected virtual bool RedirectKeys => false;
    protected virtual bool OversizedKeys => false;
    protected virtual bool AnotherIssuer => false;
    protected virtual bool AnotherOrigin => false;
    protected virtual bool SymmetricSignature => false;

    public async ValueTask InitializeAsync()
    {
        _lobby = await StartLobby();
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = "https://backend.example.test",
            [$"{C.AuthProxy.SectionKey}:Services:app:IdentityVerification"] = nameof(C.IdentityVerificationMode.BestEffort),
            [$"{C.AuthProxy.SectionKey}:Invite:TokenMetadataUrl"] = $"{BaseUrl}/metadata",
            [$"{C.AuthProxy.SectionKey}:Invite:Issuer"] = "issuer",
            [$"{C.AuthProxy.SectionKey}:Invite:Audience"] = "audience"
        });
        builder.AddIngressConfiguration().AddInvites();
        _services = builder.Services.BuildServiceProvider();
        Result = await _services.GetRequiredService<IInviteTokenValidator>().ValidateDetailed(CreateToken(), CancellationToken.None);
    }

    public async ValueTask DisposeAsync()
    {
        await _services.DisposeAsync();
        await _lobby.StopAsync();
        await _lobby.DisposeAsync();
        _rsa.Dispose();
    }

    string CreateToken()
    {
        SecurityKey key = SymmetricSignature
            ? new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_rsa.ExportSubjectPublicKeyInfoPem())) { KeyId = "known" }
            : new RsaSecurityKey(_rsa) { KeyId = "known" };
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "issuer", Audience = "audience", Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(key, SymmetricSignature ? SecurityAlgorithms.HmacSha256 : SecurityAlgorithms.RsaSha256)
        });
    }

    async Task<WebApplication> StartLobby()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        app.MapGet("/metadata", () =>
        {
            Interlocked.Increment(ref _metadataRequests);
            if (RedirectMetadata)
            {
                return Results.Redirect($"{BaseUrl}/sink");
            }
            var jwks = AnotherOrigin ? BaseUrl.Replace("127.0.0.1", "localhost", StringComparison.Ordinal) + "/sink" : $"{BaseUrl}/keys";
            return Results.Json(new { issuer = AnotherIssuer ? "another-lobby" : "issuer", audience = "audience", jwks_uri = jwks, token_signing_alg_values_supported = new[] { "RS256" } });
        });
        app.MapGet("/keys", () =>
        {
            Interlocked.Increment(ref _keyRequests);
            if (RedirectKeys)
            {
                return Results.Redirect($"{BaseUrl}/sink");
            }
            if (OversizedKeys)
            {
                return Results.Text(new string('x', InvitationTokenKeys.MaximumResponseSize + 1));
            }
            var parameters = _rsa.ExportParameters(false);
            return Results.Json(new { keys = new[] { new { kty = "RSA", use = "sig", alg = "RS256", kid = "known", n = Base64UrlEncoder.Encode(parameters.Modulus), e = Base64UrlEncoder.Encode(parameters.Exponent) } } });
        });
        app.MapGet("/sink", () =>
        {
            Interlocked.Increment(ref _sinkRequests);
            return Results.Ok();
        });
        await app.StartAsync();
        BaseUrl = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single().TrimEnd('/');
        return app;
    }
}
