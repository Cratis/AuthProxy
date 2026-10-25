// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Security.for_InvitationTokenMetadata;

public class when_the_token_is_signed_with_the_public_key_as_a_secret : given.a_lobby_issuer
{
    protected override bool SymmetricSignature => true;
    [Fact] public void should_refuse_the_token() => Assert.Equal(InviteTokenValidationResult.Invalid, Result);
    [Fact] public void should_not_fetch_for_an_untrusted_algorithm() => Assert.Equal(0, MetadataRequests);
}
