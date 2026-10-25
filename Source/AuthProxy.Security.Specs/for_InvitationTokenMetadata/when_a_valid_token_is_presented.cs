// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Security.for_InvitationTokenMetadata;

public class when_a_valid_token_is_presented : given.a_lobby_issuer
{
    [Fact] public void should_validate_through_real_registration_and_sockets() => Assert.Equal(InviteTokenValidationResult.Valid, Result);
    [Fact] public void should_read_both_documents() => Assert.Equal(1, KeyRequests);
}
