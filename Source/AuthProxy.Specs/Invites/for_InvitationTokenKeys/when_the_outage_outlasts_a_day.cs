// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_the_outage_outlasts_a_day : given.an_invitation_token_issuer
{
    async Task Establish()
    {
        await Get();
        Handler.Status = HttpStatusCode.ServiceUnavailable;
        Clock.Advance(TimeSpan.FromHours(24) + TimeSpan.FromTicks(1));
    }
    async Task Because() => Keys = await Get();
    [Fact] void should_refuse_stale_keys() => Keys.ShouldBeNull();
}
