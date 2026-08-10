// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InvitationAttestationIssuer.given;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Cratis.AuthProxy.Invites.for_InvitationAttestationIssuer;

public class when_issuing_an_identity_bound_complete_attestation : an_attestation_issuer
{
    bool _issued;
    JsonWebToken _token;

    void Because()
    {
        _issued = _issuer.TryIssueComplete(
            _state,
            new InvitationVerifiedIdentity(
                "microsoft",
                "https://login.microsoftonline.com/tenant/v2.0",
                "immutable-object-id",
                null,
                "oidc",
                _now),
            out var attestation);
        _token = Read(attestation);
    }

    [Fact] void should_issue_the_attestation() => _issued.ShouldBeTrue();
    [Fact] void should_carry_the_provider_key() => Claim(InvitationAttestationClaims.ProviderKey).ShouldEqual("microsoft");
    [Fact] void should_carry_the_tenant_specific_validated_issuer() => Claim(InvitationAttestationClaims.ProviderIssuer).ShouldEqual("https://login.microsoftonline.com/tenant/v2.0");
    [Fact] void should_carry_the_immutable_provider_subject() => Claim(InvitationAttestationClaims.ProviderSubject).ShouldEqual("immutable-object-id");
    [Fact] void should_not_invent_an_email_claim() => _token.Claims.Any(_ => _.Type == InvitationAttestationClaims.Email).ShouldBeFalse();
    [Fact] void should_not_invent_an_email_verification_claim() => _token.Claims.Any(_ => _.Type == InvitationAttestationClaims.EmailVerified).ShouldBeFalse();

    string Claim(string type) => _token.Claims.Single(_ => _.Type == type).Value;
}
