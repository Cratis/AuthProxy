// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Cratis.AuthProxy.OnBehalfSessions.given;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfAttestations.given;

public class an_on_behalf_attestation_issuer : Specification
{
    protected OnBehalfConfiguration _configuration;
    protected OnBehalfAttestations _attestations;
    protected OnBehalfSession _session;
    protected DateTimeOffset _now;

    void Establish()
    {
        _now = DateTimeOffset.FromUnixTimeSeconds(TimeProvider.System.GetUtcNow().ToUnixTimeSeconds());
        _configuration = new();
        _attestations = new(_configuration.Monitor, new ManualTime(_now));
        _session = Sessions.At(_now);
    }

    protected static JsonWebToken Read(string token) => new JsonWebTokenHandler().ReadJsonWebToken(token);

    protected static string Claim(JsonWebToken token, string type) => token.Claims.Single(_ => _.Type == type).Value;

    protected static JsonObject Actor(JsonWebToken token) =>
        JsonNode.Parse(Base64UrlEncoder.Decode(token.EncodedPayload))![OnBehalfAttestationClaims.Actor]!.AsObject();

    protected static string Digest(byte[] value) => Base64UrlEncoder.Encode(SHA256.HashData(value));

    protected Task<TokenValidationResult> Validate(string token) =>
        new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKey = _configuration.ValidationKey,
            ValidIssuer = OnBehalfConfiguration.Issuer,
            ValidAudience = OnBehalfConfiguration.Audience,
            ClockSkew = TimeSpan.Zero,
        });
}
