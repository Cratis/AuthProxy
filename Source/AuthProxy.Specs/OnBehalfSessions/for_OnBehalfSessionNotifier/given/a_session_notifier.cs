// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Cratis.AuthProxy.OnBehalfSessions.given;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessionNotifier.given;

public class a_session_notifier : Specification
{
    protected OnBehalfConfiguration _configuration;
    protected RespondingHttpMessageHandler _handler;
    protected OnBehalfSessionNotifier _notifier;
    protected OnBehalfSession _session;
    protected DateTimeOffset _now;
    protected bool _acknowledged;

    protected virtual HttpStatusCode StatusCode => HttpStatusCode.NoContent;

    void Establish()
    {
        _now = new DateTimeOffset(2026, 9, 1, 12, 0, 0, TimeSpan.Zero);
        _configuration = new();
        _handler = new(StatusCode);
        _notifier = new(
            _configuration.Monitor,
            new OnBehalfAttestations(_configuration.Monitor, new ManualTime(_now)),
            _handler.AsFactory(),
            Substitute.For<ILogger<OnBehalfSessionNotifier>>());
        _session = Sessions.At(_now);
    }

    protected JsonObject Body => JsonNode.Parse(_handler.LastRequestBytes.Span)!.AsObject();

    protected JsonWebToken Token => new JsonWebTokenHandler().ReadJsonWebToken(_handler.LastAuthorization!["Bearer ".Length..]);

    protected string BodyDigest => Base64UrlEncoder.Encode(SHA256.HashData(_handler.LastRequestBytes.Span));
}
