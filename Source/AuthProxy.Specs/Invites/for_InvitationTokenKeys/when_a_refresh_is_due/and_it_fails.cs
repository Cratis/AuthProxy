// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys.when_a_refresh_is_due;

public class and_it_fails : given.an_invitation_token_issuer
{
    async Task Establish()
    {
        await Get();
        Handler.Status = HttpStatusCode.ServiceUnavailable;
        Clock.Advance(TimeSpan.FromMinutes(5));
    }
    async Task Because() => Keys = await Get(refresh: true);
    [Fact] void should_retain_last_good_keys() => Keys!["known"].KeyId.ShouldEqual("known");
    [Fact] void should_try_to_refresh() => Handler.MetadataRequests.ShouldEqual(2);
}
