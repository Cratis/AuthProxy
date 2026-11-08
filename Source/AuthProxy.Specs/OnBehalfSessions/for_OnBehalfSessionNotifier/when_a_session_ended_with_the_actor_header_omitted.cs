// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Nodes;
using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessionNotifier.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessionNotifier;

public class when_a_session_ended_with_the_actor_header_omitted : a_session_notifier
{
    void Establish() => _configuration.Value.OnBehalf!.OmitActorHeaderOnBackChannelCalls = true;

    async Task Because() => _acknowledged = await _notifier.Ended(_session, OnBehalfSessionEndReason.GrantNotLive, _now.AddMinutes(5), CancellationToken.None);

    [Fact] void should_be_acknowledged() => _acknowledged.ShouldBeTrue();
    [Fact] void should_omit_the_actor_header() => _handler.LastHeaders.ContainsKey(Headers.OnBehalfActor).ShouldBeFalse();
    [Fact] void should_keep_the_tenant() => _handler.LastHeaders[Headers.TenantId].ShouldEqual(Sessions.Tenant);
    [Fact] void should_keep_the_legacy_tenant() => _handler.LastHeaders[Headers.LegacyTenantId].ShouldEqual(Sessions.Tenant);
    [Fact] void should_keep_the_body_actor() => Body["actor"]!["userId"]!.GetValue<string>().ShouldEqual(Sessions.ActorSubject);
    [Fact] void should_keep_the_reason() => Body["reason"]!.GetValue<string>().ShouldEqual("grant-not-live");
    [Fact] void should_keep_the_end_time() => Body["endedAt"]!.GetValue<DateTimeOffset>().ShouldEqual(_now.AddMinutes(5));
    [Fact] void should_send_the_attestation_as_a_bearer_token() => _handler.LastRequest!.Headers.Authorization!.Scheme.ShouldEqual("Bearer");
    [Fact] void should_keep_the_purpose() => Token.GetClaim(OnBehalfAttestationClaims.Purpose).Value.ShouldEqual(OnBehalfAttestationClaims.SessionEndedPurpose);
    [Fact] void should_keep_the_method() => Token.GetClaim(OnBehalfAttestationClaims.HttpMethod).Value.ShouldEqual("POST");
    [Fact] void should_keep_the_target() => Token.GetClaim(OnBehalfAttestationClaims.HttpUri).Value.ShouldEqual($"{OnBehalfConfiguration.BackendUrl}{WellKnownPaths.OnBehalfSessionEnded}");
    [Fact] void should_keep_the_body_hash() => Token.GetClaim(OnBehalfAttestationClaims.BodyHash).Value.ShouldEqual(BodyDigest);
    [Fact] void should_keep_the_actor_subject() => JsonNode.Parse(Token.GetClaim(OnBehalfAttestationClaims.Actor).Value)![OnBehalfAttestationClaims.ActorSubject]!.GetValue<string>().ShouldEqual(Sessions.ActorSubject);
    [Fact] void should_keep_the_actor_provider() => JsonNode.Parse(Token.GetClaim(OnBehalfAttestationClaims.Actor).Value)![OnBehalfAttestationClaims.ActorIdentityProvider]!.GetValue<string>().ShouldEqual(Sessions.ActorProvider);
    [Fact] void should_keep_the_signed_tenant() => Token.GetClaim(OnBehalfAttestationClaims.Tenant).Value.ShouldEqual(Sessions.Tenant);
    [Fact] void should_keep_the_subject() => Token.GetClaim(OnBehalfAttestationClaims.Subject).Value.ShouldEqual(Sessions.Subject);
    [Fact] void should_keep_the_issue() => Token.GetClaim(OnBehalfAttestationClaims.Issue).Value.ShouldEqual(Sessions.Issue);
    [Fact] void should_keep_the_session() => Token.GetClaim(OnBehalfAttestationClaims.SessionId).Value.ShouldEqual(_session.SessionId);
    [Fact] void should_not_require_an_actor_header_hash() => Token.TryGetClaim(OnBehalfAttestationClaims.ActorHash, out _).ShouldBeFalse();
}
