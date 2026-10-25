// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Security.for_InvitationTokenMetadata;

public class when_the_metadata_names_another_lobby : given.a_lobby_issuer
{
    protected override bool AnotherIssuer => true;
    [Fact] public void should_refuse_the_token() => Assert.Equal(InviteTokenValidationResult.Invalid, Result);
    [Fact] public void should_not_read_its_keys() => Assert.Equal(0, KeyRequests);
}
