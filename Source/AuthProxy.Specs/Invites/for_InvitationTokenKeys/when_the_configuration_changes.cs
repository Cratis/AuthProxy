// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_the_configuration_changes : given.an_invitation_token_issuer
{
    async Task Establish() => await Get();
    async Task Because() => Keys = await Provider.GetSigningKeys(new() { TokenMetadataUrl = Invite.TokenMetadataUrl, Issuer = "different", Audience = "different" }, CancellationToken.None);
    [Fact] void should_not_reuse_old_keys() => Keys.ShouldBeNull();
    [Fact] void should_fetch_new_metadata() => Handler.MetadataRequests.ShouldEqual(2);
}
