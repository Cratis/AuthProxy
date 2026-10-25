// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_the_metadata_names_another_audience : given.an_invitation_token_issuer
{
    IReadOnlyDictionary<string, Microsoft.IdentityModel.Tokens.SecurityKey>? _rejected;
    int _keyRequestsBeforeRetry;
    async Task Because()
    {
        Handler.Audience = "another";
        _rejected = await Get();
        _keyRequestsBeforeRetry = Handler.KeyRequests;
        Handler.Audience = "audience";
        Clock.Advance(TimeSpan.FromSeconds(30));
        Keys = await Get();
    }
    [Fact] void should_reject_mismatched_metadata() => _rejected.ShouldBeNull();
    [Fact] void should_not_fetch_its_keys() => _keyRequestsBeforeRetry.ShouldEqual(0);
    [Fact] void should_accept_good_metadata_after_backoff() => Keys!["known"].KeyId.ShouldEqual("known");
}
