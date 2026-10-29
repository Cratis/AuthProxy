// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_a_response_without_content_length_exceeds_the_size_limit : given.an_invitation_token_issuer
{
    void Establish()
    {
        Handler.OversizedBody = new string('x', InvitationTokenKeys.MaximumResponseSize + 1);
        Handler.UnknownLength = true;
    }
    async Task Because() => Keys = await Get();
    [Fact] void should_reject() => Keys.ShouldBeNull();
    [Fact] void should_not_fetch_keys() => Handler.KeyRequests.ShouldEqual(0);
}
