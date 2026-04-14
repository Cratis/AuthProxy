// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteTokenValidator;

public class when_getting_claim_from_token_that_does_not_have_the_claim : Specification
{
    InviteTokenValidator _validator;
    string _token;
    bool _result;
    string _claimValue;

    void Establish()
    {
        var (privateKey, publicKeyPem) = TokenFixture.GenerateKeyPair();
        _token = TokenFixture.CreateToken(privateKey);

        var config = new IngressConfig
        {
            Invite = new InviteConfig { PublicKeyPem = publicKeyPem }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<IngressConfig>>();
        optionsMonitor.CurrentValue.Returns(config);

        _validator = new InviteTokenValidator(optionsMonitor);
    }

    void Because() => _result = _validator.TryGetClaim(_token, "nonexistent_claim", out _claimValue);

    [Fact] void should_return_false() => _result.ShouldBeFalse();
    [Fact] void should_return_empty_claim_value() => _claimValue.ShouldEqual(string.Empty);
}
