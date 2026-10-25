// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_keys_are_first_requested : given.an_invitation_token_issuer
{
    async Task Because() => Keys = await Get();
    [Fact] void should_fetch_metadata_once() => Handler.MetadataRequests.ShouldEqual(1);
    [Fact] void should_fetch_jwks_once() => Handler.KeyRequests.ShouldEqual(1);
    [Fact] void should_index_the_key_by_kid() => Keys!["known"].KeyId.ShouldEqual("known");
}
