// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Security.for_InvitationTokenMetadata;

public class when_the_jwks_is_larger_than_the_limit : given.a_lobby_issuer
{
    protected override bool OversizedKeys => true;
    [Fact] public void should_refuse_the_token() => Assert.Equal(InviteTokenValidationResult.Invalid, Result);
}
