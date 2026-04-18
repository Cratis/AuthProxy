// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteTokenValidator;

public class when_public_key_is_missing : Specification
{
    InviteTokenValidationResult _result;

    void Establish()
    {
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(new C.AuthProxy
        {
            Invite = new C.Invite
            {
                PublicKeyPem = string.Empty
            }
        });

        var validator = new InviteTokenValidator(options);
        _result = validator.ValidateDetailed("any-token");
    }

    [Fact]
    void should_report_invalid() => _result.ShouldEqual(InviteTokenValidationResult.Invalid);
}
