// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InvitationAttestationIssuer.given;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Invites.for_InvitationAttestationIssuer;

public class when_issuing_a_stage_attestation : an_attestation_issuer
{
    bool _issued;
    string _attestation;
    TokenValidationResult _validation;
    JsonWebToken _token;

    async Task Because()
    {
        _issued = _issuer.TryIssueStage(_state, out _attestation);
        _token = Read(_attestation);
        _validation = await Validate(_attestation);
    }

    [Fact] void should_issue_the_attestation() => _issued.ShouldBeTrue();
    [Fact] void should_sign_a_valid_token() => _validation.IsValid.ShouldBeTrue();
    [Fact] void should_identify_the_signing_key() => _token.Kid.ShouldEqual(KeyId);
    [Fact] void should_have_the_stage_purpose() => _token.Claims.Single(_ => _.Type == InvitationAttestationClaims.Purpose).Value.ShouldEqual(InvitationAttestationClaims.StagePurpose);
    [Fact] void should_bind_the_tenant() => _token.Claims.Single(_ => _.Type == InvitationAttestationClaims.TenantId).Value.ShouldEqual(TenantId);
    [Fact] void should_bind_the_invitation() => _token.Claims.Single(_ => _.Type == InvitationAttestationClaims.InvitationId).Value.ShouldEqual(InvitationId);
    [Fact] void should_bind_the_transaction() => _token.Claims.Single(_ => _.Type == InvitationAttestationClaims.InvitationTransaction).Value.ShouldEqual(Transaction);
    [Fact] void should_bind_the_challenge() => _token.Claims.Single(_ => _.Type == InvitationAttestationClaims.InvitationChallenge).Value.ShouldEqual(Challenge);
    [Fact] void should_bind_the_capability_hash() => _token.Claims.Single(_ => _.Type == InvitationAttestationClaims.CapabilityHash).Value.ShouldEqual(CapabilityHash);
    [Fact] void should_have_a_unique_identifier() => _token.Id.ShouldNotBeEmpty();
    [Fact] void should_have_the_configured_issuer() => _token.Issuer.ShouldEqual(Issuer);
    [Fact] void should_have_the_configured_audience() => _token.Audiences.ShouldContain(Audience);
    [Fact] void should_be_valid_from_the_issue_time() => _token.ValidFrom.ShouldEqual(_now.UtcDateTime);
    [Fact] void should_expire_after_the_configured_lifetime() => _token.ValidTo.ShouldEqual(_now.AddSeconds(60).UtcDateTime);
}
