// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_the_metadata_answers_with_a_redirect : given.an_invitation_token_issuer
{
    void Establish() => Handler.Status = HttpStatusCode.Redirect;
    async Task Because() => Keys = await Get();
    [Fact] void should_reject() => Keys.ShouldBeNull();
    [Fact] void should_make_only_the_metadata_request() => Handler.MetadataRequests.ShouldEqual(1);
    [Fact] void should_not_follow_the_location() => Handler.KeyRequests.ShouldEqual(0);
}
