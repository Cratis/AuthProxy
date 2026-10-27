// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.given;

public class a_grant_check : Specification
{
    protected OnBehalfConfiguration _configuration;
    protected RespondingHttpMessageHandler _handler;
    protected OnBehalfGrants _grants;
    protected OnBehalfSession _session;
    protected ClientPrincipal _actor;
    protected DateTimeOffset _now;
    protected OnBehalfGrant _result;

    protected virtual HttpStatusCode StatusCode => HttpStatusCode.OK;

    protected virtual string? Body => null;

    void Establish()
    {
        _now = new DateTimeOffset(2026, 9, 1, 12, 0, 0, TimeSpan.Zero);
        _configuration = new();
        _handler = new(StatusCode, Body);
        var time = new ManualTime(_now);
        _grants = new(
            _configuration.Monitor,
            new OnBehalfAttestations(_configuration.Monitor, time),
            _handler.AsFactory(),
            time,
            Substitute.For<ILogger<OnBehalfGrants>>());
        _session = Sessions.At(_now);
        _actor = new ClientPrincipal { IdentityProvider = Sessions.ActorProvider, UserId = Sessions.ActorSubject, UserDetails = Sessions.ActorName };
    }

    protected async Task Check() => _result = await _grants.Check(_session, _actor, CancellationToken.None);

    protected string LiveAnswer(string subject = Sessions.Subject, string validUntil = "2026-09-01T13:00:00Z", string live = "true") =>
        $$$"""{ "live": {{{live}}}, "validUntil": "{{{validUntil}}}", "principal": { "identityProvider": "microsoft", "userId": "{{{subject}}}", "userDetails": "user@example.com", "userRoles": ["user"], "claims": [{ "typ": "tid", "val": "tenant" }, { "typ": "urn:cratis:bearer:scope", "val": "smuggled" }] } }""";
}
