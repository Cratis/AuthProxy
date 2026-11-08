// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.given;
using Cratis.AuthProxy.OnBehalfSessions.given;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.when_checking_a_grant;

public class and_the_actor_header_is_omitted : a_grant_check
{
    JsonWebToken _token;
    JsonObject _actorClaim;

    protected override string? Body => LiveAnswer();

    void Establish() => _configuration.Value.OnBehalf!.OmitActorHeaderOnBackChannelCalls = true;

    async Task Because()
    {
        await Check();
        _token = new JsonWebTokenHandler().ReadJsonWebToken(_handler.LastAuthorization!["Bearer ".Length..]);
        _actorClaim = JsonNode.Parse(_token.GetClaim(OnBehalfAttestationClaims.Actor).Value)!.AsObject();
    }

    [Fact] void should_be_live() => _result.IsLive.ShouldBeTrue();
    [Fact] void should_omit_the_actor_header() => _handler.LastHeaders.ContainsKey(Headers.OnBehalfActor).ShouldBeFalse();
    [Fact] void should_keep_the_tenant() => _handler.LastHeaders[Headers.TenantId].ShouldEqual(Sessions.Tenant);
    [Fact] void should_keep_the_legacy_tenant() => _handler.LastHeaders[Headers.LegacyTenantId].ShouldEqual(Sessions.Tenant);
    [Fact] void should_keep_the_actor_query() => QueryHelpers.ParseQuery(_handler.LastRequest!.RequestUri!.Query)["actor"].ToString().ShouldEqual(Sessions.ActorSubject);
    [Fact] void should_send_the_attestation_as_a_bearer_token() => _handler.LastRequest!.Headers.Authorization!.Scheme.ShouldEqual("Bearer");
    [Fact] void should_keep_the_purpose() => _token.GetClaim(OnBehalfAttestationClaims.Purpose).Value.ShouldEqual(OnBehalfAttestationClaims.GrantCheckPurpose);
    [Fact] void should_keep_the_method() => _token.GetClaim(OnBehalfAttestationClaims.HttpMethod).Value.ShouldEqual("GET");
    [Fact] void should_keep_the_target() => _token.GetClaim(OnBehalfAttestationClaims.HttpUri).Value.ShouldEqual($"{OnBehalfConfiguration.BackendUrl}{WellKnownPaths.OnBehalfGrants}");
    [Fact] void should_keep_the_body_hash() => _token.GetClaim(OnBehalfAttestationClaims.BodyHash).Value.ShouldEqual(Base64UrlEncoder.Encode(SHA256.HashData(_handler.LastRequestBytes.Span)));
    [Fact] void should_keep_the_actor_subject() => _actorClaim[OnBehalfAttestationClaims.ActorSubject]!.GetValue<string>().ShouldEqual(Sessions.ActorSubject);
    [Fact] void should_keep_the_actor_provider() => _actorClaim[OnBehalfAttestationClaims.ActorIdentityProvider]!.GetValue<string>().ShouldEqual(Sessions.ActorProvider);
    [Fact] void should_keep_the_signed_tenant() => _token.GetClaim(OnBehalfAttestationClaims.Tenant).Value.ShouldEqual(Sessions.Tenant);
    [Fact] void should_keep_the_subject() => _token.GetClaim(OnBehalfAttestationClaims.Subject).Value.ShouldEqual(Sessions.Subject);
    [Fact] void should_keep_the_issue() => _token.GetClaim(OnBehalfAttestationClaims.Issue).Value.ShouldEqual(Sessions.Issue);
    [Fact] void should_keep_the_session() => _token.GetClaim(OnBehalfAttestationClaims.SessionId).Value.ShouldEqual(_session.SessionId);
    [Fact] void should_not_require_an_actor_header_hash() => _token.TryGetClaim(OnBehalfAttestationClaims.ActorHash, out _).ShouldBeFalse();
}
