// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfAttestations.given;
using Cratis.AuthProxy.OnBehalfSessions.given;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfAttestations;

public class when_issuing_a_call_token : an_on_behalf_attestation_issuer
{
    static readonly Uri _target = new("https://portal.internal/.cratis/on-behalf/sessions/started?ignored=1");
    static readonly byte[] _body = Encoding.UTF8.GetBytes("{\"sessionId\":\"session-1\"}");

    JsonWebToken _token;

    void Because()
    {
        _attestations.TryIssueForCall(OnBehalfAttestationClaims.SessionStartedPurpose, _session, HttpMethod.Post, _target, _body, out var token);
        _token = Read(token);
    }

    [Fact] void should_name_its_purpose() => Claim(_token, OnBehalfAttestationClaims.Purpose).ShouldEqual(OnBehalfAttestationClaims.SessionStartedPurpose);
    [Fact] void should_bind_the_method() => Claim(_token, OnBehalfAttestationClaims.HttpMethod).ShouldEqual("POST");
    [Fact] void should_bind_the_route_without_its_query() => Claim(_token, OnBehalfAttestationClaims.HttpUri).ShouldEqual("https://portal.internal/.cratis/on-behalf/sessions/started");
    [Fact] void should_bind_the_exact_body() => Claim(_token, OnBehalfAttestationClaims.BodyHash).ShouldEqual(Digest(_body));
    [Fact] void should_name_the_represented_user() => Claim(_token, OnBehalfAttestationClaims.Subject).ShouldEqual(Sessions.Subject);
    [Fact] void should_bind_the_session() => Claim(_token, OnBehalfAttestationClaims.SessionId).ShouldEqual(_session.SessionId);
}
