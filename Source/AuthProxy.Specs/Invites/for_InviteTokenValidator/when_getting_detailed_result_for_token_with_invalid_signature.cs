// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteTokenValidator;

public class when_getting_detailed_result_for_token_with_invalid_signature : Specification
{
    InviteTokenValidator _validator;
    string _token;
    InviteTokenValidationResult _result;

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

    void Because() => _result = _validator.ValidateDetailed(_token);

    [Fact] void should_return_invalid() => _result.ShouldEqual(InviteTokenValidationResult.Invalid);
}
