// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_nothing_is_cached_and_the_metadata_is_unavailable : given.an_invitation_token_issuer
{
    void Establish() => Handler.Status = HttpStatusCode.ServiceUnavailable;
    async Task Because()
    {
        await Get();
        Keys = await Get();
    }
    [Fact] void should_have_no_keys() => Keys.ShouldBeNull();
    [Fact] void should_back_off() => Handler.MetadataRequests.ShouldEqual(1);
}
