// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteTokenValidator;

public class when_using_only_a_pinned_key : given.a_metadata_validated_token
{
    void Establish()
    {
        Invite.TokenMetadataUrl = string.Empty;
        Invite.PublicKeyPem = SigningKey.Rsa.ExportSubjectPublicKeyInfoPem();
    }
    async Task Because() => Result = await Validator.ValidateDetailed(Token, CancellationToken.None);
    [Fact] void should_keep_accepting_the_pinned_key() => Result.ShouldEqual(InviteTokenValidationResult.Valid);
    [Fact] void should_never_fetch_metadata() => Keys.ReceivedCalls().ShouldBeEmpty();
}
