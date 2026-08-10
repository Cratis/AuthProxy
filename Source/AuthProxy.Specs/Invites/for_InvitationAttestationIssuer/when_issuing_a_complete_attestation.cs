// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InvitationAttestationIssuer.given;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Cratis.AuthProxy.Invites.for_InvitationAttestationIssuer;

public class when_issuing_a_complete_attestation : an_attestation_issuer
{
    const string Email = "invitee@example.com";
    readonly DateTimeOffset _authenticatedAt = new(2026, 8, 10, 1, 1, 0, TimeSpan.Zero);
    bool _issued;
    JsonWebToken _token;

    void Because()
    {
        _issued = _issuer.TryIssueComplete(
            _state,
            new InvitationVerifiedIdentity(
                "entra-workforce",
                "https://login.example.com/tenant",
                "provider-subject",
                Email,
                "urn:mfa",
                _authenticatedAt),
            out var attestation);
        _token = Read(attestation);
    }

    [Fact] void should_issue_the_attestation() => _issued.ShouldBeTrue();
    [Fact] void should_have_the_complete_purpose() => Claim(InvitationAttestationClaims.Purpose).ShouldEqual(InvitationAttestationClaims.CompletePurpose);
    [Fact] void should_carry_the_provider_key() => Claim(InvitationAttestationClaims.ProviderKey).ShouldEqual("entra-workforce");
    [Fact] void should_carry_the_provider_issuer() => Claim(InvitationAttestationClaims.ProviderIssuer).ShouldEqual("https://login.example.com/tenant");
    [Fact] void should_carry_the_provider_subject() => Claim(InvitationAttestationClaims.ProviderSubject).ShouldEqual("provider-subject");
    [Fact] void should_carry_the_verified_email() => Claim(InvitationAttestationClaims.Email).ShouldEqual(Email);
    [Fact] void should_attest_that_the_email_is_verified() => Claim(InvitationAttestationClaims.EmailVerified).ShouldEqual(bool.TrueString.ToLowerInvariant());
    [Fact] void should_carry_provider_assurance() => Claim(InvitationAttestationClaims.Assurance).ShouldEqual("urn:mfa");
    [Fact] void should_carry_the_authentication_time() => Claim(InvitationAttestationClaims.AuthenticatedAt).ShouldEqual(_authenticatedAt.ToUnixTimeSeconds().ToString());

    string Claim(string type) => _token.Claims.Single(_ => _.Type == type).Value;
}
