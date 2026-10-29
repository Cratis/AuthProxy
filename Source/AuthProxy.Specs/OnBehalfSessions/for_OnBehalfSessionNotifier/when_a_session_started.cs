// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessionNotifier.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessionNotifier;

public class when_a_session_started : a_session_notifier
{
    async Task Because() => _acknowledged = await _notifier.Started(_session, OnBehalfGrant.Live(_now.AddHours(2), Sessions.Represented()), CancellationToken.None);

    [Fact] void should_be_acknowledged() => _acknowledged.ShouldBeTrue();
    [Fact] void should_post() => _handler.LastRequest!.Method.ShouldEqual(HttpMethod.Post);
    [Fact] void should_post_to_the_started_endpoint() => _handler.LastRequest!.RequestUri!.ToString().ShouldEqual($"{OnBehalfConfiguration.BackendUrl}{WellKnownPaths.OnBehalfSessionStarted}");
    [Fact] void should_name_the_session() => Body["sessionId"]!.GetValue<string>().ShouldEqual(_session.SessionId);
    [Fact] void should_name_the_tenant() => Body["tenant"]!.GetValue<string>().ShouldEqual(Sessions.Tenant);
    [Fact] void should_name_the_issue() => Body["issue"]!.GetValue<string>().ShouldEqual(Sessions.Issue);
    [Fact] void should_name_the_represented_user() => Body["subject"]!.GetValue<string>().ShouldEqual(Sessions.Subject);
    [Fact] void should_name_the_actor() => Body["actor"]!["userId"]!.GetValue<string>().ShouldEqual(Sessions.ActorSubject);
    [Fact] void should_name_the_actors_provider() => Body["actor"]!["identityProvider"]!.GetValue<string>().ShouldEqual(Sessions.ActorProvider);
    [Fact] void should_carry_when_it_expires() => Body["expiresAt"]!.GetValue<DateTimeOffset>().ShouldEqual(_session.ExpiresAt);
    [Fact] void should_carry_the_grants_validity() => Body["grantValidUntil"]!.GetValue<DateTimeOffset>().ShouldEqual(_now.AddHours(2));
    [Fact] void should_send_the_tenant_header() => _handler.LastHeaders[Headers.TenantId].ShouldEqual(Sessions.Tenant);
    [Fact] void should_sign_it_as_a_start() => Token.GetClaim(OnBehalfAttestationClaims.Purpose).Value.ShouldEqual(OnBehalfAttestationClaims.SessionStartedPurpose);
    [Fact] void should_sign_the_exact_body() => Token.GetClaim(OnBehalfAttestationClaims.BodyHash).Value.ShouldEqual(BodyDigest);
}
