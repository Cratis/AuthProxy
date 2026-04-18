// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteTokenValidator;

public class when_trying_to_get_claim_from_malformed_token : Specification
{
    bool _success;
    string _claimValue;

    void Establish()
    {
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(new C.AuthProxy
        {
            Invite = new C.Invite
            {
                PublicKeyPem = "unused"
            }
        });

        var validator = new InviteTokenValidator(options);
        _success = validator.TryGetClaim("not-a-jwt", "sub", out _claimValue);
    }

    [Fact]
    void should_return_false() => _success.ShouldBeFalse();

    [Fact]
    void should_return_empty_claim_value() => _claimValue.ShouldEqual(string.Empty);
}
