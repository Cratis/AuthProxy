// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfAttestations.given;
using Cratis.AuthProxy.OnBehalfSessions.given;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfAttestations;

/// <summary>
/// The assertion forwarded with every on-behalf request is the only thing that lets an application believe the two
/// identity headers, so every fact it binds is pinned here against what a verifier reads.
/// </summary>
public class when_issuing_a_forward_assertion : an_on_behalf_attestation_issuer
{
    const string PrincipalHeader = "cmVwcmVzZW50ZWQ=";
    const string ActorHeader = "YWN0b3I=";

    bool _issued;
    JsonWebToken _token;
    TokenValidationResult _validation;

    async Task Because()
    {
        _issued = _attestations.TryIssueForForward(_session, PrincipalHeader, ActorHeader, out var token);
        _token = Read(token);
        _validation = await Validate(token);
    }

    [Fact] void should_issue_it() => _issued.ShouldBeTrue();
    [Fact] void should_verify_against_the_published_key_issuer_and_audience() => _validation.IsValid.ShouldBeTrue();
    [Fact] void should_name_its_purpose() => Claim(_token, OnBehalfAttestationClaims.Purpose).ShouldEqual(OnBehalfAttestationClaims.ForwardPurpose);
    [Fact] void should_name_the_represented_user_as_the_subject() => Claim(_token, OnBehalfAttestationClaims.Subject).ShouldEqual(Sessions.Subject);
    [Fact] void should_name_the_actor_subject() => Actor(_token)[OnBehalfAttestationClaims.ActorSubject]!.GetValue<string>().ShouldEqual(Sessions.ActorSubject);
    [Fact] void should_name_the_actor_identity_provider() => Actor(_token)[OnBehalfAttestationClaims.ActorIdentityProvider]!.GetValue<string>().ShouldEqual(Sessions.ActorProvider);
    [Fact] void should_bind_the_tenant() => Claim(_token, OnBehalfAttestationClaims.Tenant).ShouldEqual(Sessions.Tenant);
    [Fact] void should_bind_the_issue() => Claim(_token, OnBehalfAttestationClaims.Issue).ShouldEqual(Sessions.Issue);
    [Fact] void should_bind_the_session() => Claim(_token, OnBehalfAttestationClaims.SessionId).ShouldEqual(_session.SessionId);
    [Fact] void should_bind_the_exact_principal_header() => Claim(_token, OnBehalfAttestationClaims.PrincipalHash).ShouldEqual(Digest(Encoding.ASCII.GetBytes(PrincipalHeader)));
    [Fact] void should_bind_the_exact_actor_header() => Claim(_token, OnBehalfAttestationClaims.ActorHash).ShouldEqual(Digest(Encoding.ASCII.GetBytes(ActorHeader)));
    [Fact] void should_name_the_signing_key() => _token.Kid.ShouldEqual(OnBehalfConfiguration.KeyId);
    [Fact] void should_carry_a_replay_identifier() => string.IsNullOrEmpty(_token.Id).ShouldBeFalse();
    [Fact] void should_expire_within_a_minute() => (_token.ValidTo - _token.IssuedAt).ShouldEqual(TimeSpan.FromSeconds(60));
}
