// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessionNotifier.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessionNotifier;

public class when_a_session_ended : a_session_notifier
{
    async Task Because() => _acknowledged = await _notifier.Ended(_session, OnBehalfSessionEndReason.GrantNotLive, _now.AddMinutes(5), CancellationToken.None);

    [Fact] void should_be_acknowledged() => _acknowledged.ShouldBeTrue();
    [Fact] void should_post() => _handler.LastRequest!.Method.ShouldEqual(HttpMethod.Post);
    [Fact] void should_post_to_the_ended_endpoint() => _handler.LastRequest!.RequestUri!.AbsolutePath.ShouldEqual(WellKnownPaths.OnBehalfSessionEnded);
    [Fact] void should_name_the_reason() => Body["reason"]!.GetValue<string>().ShouldEqual("grant-not-live");
    [Fact] void should_carry_when_it_ended() => Body["endedAt"]!.GetValue<DateTimeOffset>().ShouldEqual(_now.AddMinutes(5));
    [Fact] void should_carry_when_it_started() => Body["startedAt"]!.GetValue<DateTimeOffset>().ShouldEqual(_now);
    [Fact] void should_send_the_tenant_header() => _handler.LastHeaders[Headers.TenantId].ShouldEqual(Sessions.Tenant);
    [Fact] void should_send_the_legacy_tenant_header() => _handler.LastHeaders[Headers.LegacyTenantId].ShouldEqual(Sessions.Tenant);
    [Fact] void should_send_the_actor_header() => _handler.LastHeaders[Headers.OnBehalfActor].ShouldEqual(OnBehalfApplication.Describe(_session.Actor).ToBase64());
    [Fact] void should_send_the_attestation_as_a_bearer_token() => _handler.LastRequest!.Headers.Authorization!.Scheme.ShouldEqual("Bearer");
    [Fact] void should_sign_the_method() => Token.GetClaim(OnBehalfAttestationClaims.HttpMethod).Value.ShouldEqual(_handler.LastRequest!.Method.Method);
    [Fact] void should_sign_the_target() => Token.GetClaim(OnBehalfAttestationClaims.HttpUri).Value.ShouldEqual(_handler.LastRequest!.RequestUri!.GetLeftPart(UriPartial.Path));
    [Fact] void should_sign_it_as_an_end() => Token.GetClaim(OnBehalfAttestationClaims.Purpose).Value.ShouldEqual(OnBehalfAttestationClaims.SessionEndedPurpose);
    [Fact] void should_sign_the_exact_body() => Token.GetClaim(OnBehalfAttestationClaims.BodyHash).Value.ShouldEqual(BodyDigest);
}
