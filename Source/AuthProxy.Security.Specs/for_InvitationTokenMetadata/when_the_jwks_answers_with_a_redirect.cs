// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Security.for_InvitationTokenMetadata;

public class when_the_jwks_answers_with_a_redirect : given.a_lobby_issuer
{
    protected override bool RedirectKeys => true;
    [Fact] public void should_refuse_the_token() => Assert.Equal(InviteTokenValidationResult.Invalid, Result);
    [Fact] public void should_never_follow_the_redirect() => Assert.Equal(0, SinkRequests);
}
