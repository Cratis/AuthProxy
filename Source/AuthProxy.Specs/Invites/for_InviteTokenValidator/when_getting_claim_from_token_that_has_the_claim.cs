// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteTokenValidator;

public class when_getting_claim_from_token_that_has_the_claim : Specification
{
    const string ClaimType = "tenant_id";
    const string ClaimValue = "some-tenant-guid";

    InviteTokenValidator _validator;
    string _token;
    bool _result;
    string _claimValue;

    void Establish()
    {
        var (privateKey, publicKeyPem) = TokenFixture.GenerateKeyPair();
        _token = TokenFixture.CreateToken(
            privateKey,
            additionalClaims: [new Claim(ClaimType, ClaimValue)]);

        var config = new C.AuthProxy
        {
            Invite = new C.Invite { PublicKeyPem = publicKeyPem }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        _validator = new InviteTokenValidator(optionsMonitor);
    }

    void Because() => _result = _validator.TryGetClaim(_token, ClaimType, out _claimValue);

    [Fact] void should_return_true() => _result.ShouldBeTrue();
    [Fact] void should_return_the_claim_value() => _claimValue.ShouldEqual(ClaimValue);
}
