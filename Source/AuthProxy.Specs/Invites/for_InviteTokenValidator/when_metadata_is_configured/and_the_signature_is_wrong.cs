// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Invites.for_InviteTokenValidator.when_metadata_is_configured;

public class and_the_signature_is_wrong : given.a_metadata_validated_token
{
    void Establish()
    {
        using var wrong = RSA.Create(2048);
        PublicKeys["known"] = new RsaSecurityKey(wrong.ExportParameters(false)) { KeyId = "known" };
    }
    async Task Because() => Result = await Validator.ValidateDetailed(Token, CancellationToken.None);
    [Fact] void should_reject() => Result.ShouldEqual(InviteTokenValidationResult.Invalid);
    [Fact] void should_not_refresh_for_a_known_kid() => Keys.DidNotReceive().GetSigningKeys(Invite, Arg.Any<CancellationToken>(), true);
}
