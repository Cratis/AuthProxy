// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteTokenValidator;

public class when_token_signature_is_invalid : Specification
{
    InviteTokenValidator _validator;
    string _token;
    bool _result;

    void Establish()
    {
        // Sign with a different key than the one configured for validation.
        var (signingKey, _) = TokenFixture.GenerateKeyPair();
        var (_, publicKeyPem) = TokenFixture.GenerateKeyPair();

        _token = TokenFixture.CreateToken(signingKey, "test-issuer", "test-audience");

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

    void Because() => _result = _validator.Validate(_token);

    [Fact] void should_return_false() => _result.ShouldBeFalse();
}
