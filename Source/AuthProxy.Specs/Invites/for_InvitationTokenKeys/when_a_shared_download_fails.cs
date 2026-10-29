// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_a_shared_download_fails : given.an_invitation_token_issuer
{
    IReadOnlyDictionary<string, Microsoft.IdentityModel.Tokens.SecurityKey>? _failedKeys;
    int _requestsDuringBackoff;

    async Task Because()
    {
        Handler.Delay = true;
        Handler.Status = HttpStatusCode.ServiceUnavailable;
        var fetching = Get();
        await Handler.Started.Task;
        Clock.Advance(TimeSpan.FromSeconds(25));
        Handler.Release.SetResult();
        _failedKeys = await fetching;
        Handler.Status = HttpStatusCode.OK;
        Clock.Advance(InvitationTokenKeys.RequestedRefreshInterval - TimeSpan.FromTicks(1));
        await Get();
        await Get(refresh: true);
        _requestsDuringBackoff = Handler.MetadataRequests;
        Clock.Advance(TimeSpan.FromTicks(1));
        Keys = await Get();
    }

    [Fact] void should_fail_closed_on_the_failed_download() => _failedKeys.ShouldBeNull();
    [Fact] void should_back_off_normal_and_requested_downloads_from_the_failure_time() => _requestsDuringBackoff.ShouldEqual(1);
    [Fact] void should_retry_at_the_failure_backoff_deadline() => Handler.MetadataRequests.ShouldEqual(2);
    [Fact] void should_load_keys_after_recovery() => Keys!["known"].KeyId.ShouldEqual("known");
}
