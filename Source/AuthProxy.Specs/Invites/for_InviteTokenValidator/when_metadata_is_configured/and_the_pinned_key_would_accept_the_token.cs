// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteTokenValidator.when_metadata_is_configured;

public class and_the_pinned_key_would_accept_the_token : given.a_metadata_validated_token
{
    void Establish()
    {
        Invite.PublicKeyPem = SigningKey.Rsa.ExportSubjectPublicKeyInfoPem();
        PublicKeys.Clear();
    }
    async Task Because() => Result = await Validator.ValidateDetailed(Token, CancellationToken.None);
    [Fact] void should_not_fall_back_to_the_pinned_key() => Result.ShouldEqual(InviteTokenValidationResult.Invalid);
}
