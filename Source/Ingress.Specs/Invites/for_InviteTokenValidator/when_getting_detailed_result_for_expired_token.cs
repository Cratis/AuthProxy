// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.Invites.for_InviteTokenValidator;

public class when_getting_detailed_result_for_expired_token : Specification
{
    InviteTokenValidator _validator;
    string _token;
    InviteTokenValidationResult _result;

    void Establish()
    {
        var (privateKey, publicKeyPem) = TokenFixture.GenerateKeyPair();
        _token = TokenFixture.CreateToken(
            privateKey,
            "test-issuer",
            "test-audience",
            expires: DateTime.UtcNow.AddMinutes(-10),
            notBefore: DateTime.UtcNow.AddMinutes(-20));

        var config = new IngressConfig
        {
            Invite = new InviteConfig
            {
                PublicKeyPem = publicKeyPem,
                Issuer = "test-issuer",
                Audience = "test-audience",
            }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<IngressConfig>>();
        optionsMonitor.CurrentValue.Returns(config);

        _validator = new InviteTokenValidator(optionsMonitor);
    }

    void Because() => _result = _validator.ValidateDetailed(_token);

    [Fact] void should_return_expired() => _result.ShouldEqual(InviteTokenValidationResult.Expired);
}
