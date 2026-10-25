// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_concurrent_callers_need_the_first_fetch : given.an_invitation_token_issuer
{
    IReadOnlyDictionary<string, Microsoft.IdentityModel.Tokens.SecurityKey>?[] _results;
    bool _allWaiting;

    async Task Because()
    {
        Handler.Delay = true;
        var requests = Enumerable.Range(0, 20).Select(_ => Get()).ToArray();
        await Handler.Started.Task;
        _allWaiting = requests.All(request => !request.IsCompleted);
        Handler.Release.SetResult();
        _results = await Task.WhenAll(requests);
    }

    [Fact] void should_wait_for_the_shared_download() => _allWaiting.ShouldBeTrue();
    [Fact] void should_return_keys_to_every_caller() => Assert.All(_results, result => result!["known"].KeyId.ShouldEqual("known"));
    [Fact] void should_return_the_same_key_snapshot() => Assert.All(_results, result => Assert.Same(_results[0], result));
    [Fact] void should_download_metadata_once() => Handler.MetadataRequests.ShouldEqual(1);
    [Fact] void should_download_jwks_once() => Handler.KeyRequests.ShouldEqual(1);
}
