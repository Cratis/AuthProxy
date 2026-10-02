// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerIssuerMetadata;

public class when_an_ordinary_lookup_precedes_a_requested_refresh : given.a_cached_issuer
{
    IReadOnlyCollection<SecurityKey>? _before;
    IReadOnlyCollection<SecurityKey>? _during;
    IReadOnlyCollection<SecurityKey>? _refreshed;
    bool _refreshWaited;

    void Establish() => Handler.Delay = true;

    async Task Because()
    {
        // Another caller looks up known keys between unknown-key detection and the caller's refresh operation.
        _before = await Metadata.GetSigningKeys(Issuer, CancellationToken.None);
        var refresh = Metadata.GetSigningKeys(Issuer, CancellationToken.None, refresh: true);
        await Handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        _during = await Metadata.GetSigningKeys(Issuer, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        _refreshWaited = !refresh.IsCompleted;
        Handler.Release.TrySetResult();
        _refreshed = await refresh.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
    }

    [Fact] void should_not_refresh_for_the_unrelated_lookup() => _before!.Single().KeyId.ShouldEqual("known");
    [Fact] void should_return_cached_keys_to_an_ordinary_caller_during_refresh() => _during!.Single().KeyId.ShouldEqual("known");
    [Fact] void should_keep_the_requesting_caller_waiting_for_its_refresh() => _refreshWaited.ShouldBeTrue();
    [Fact] void should_return_the_rotated_key_to_the_requesting_caller() => _refreshed!.Single().KeyId.ShouldEqual("rotated");
    [Fact] void should_retrieve_only_for_the_initial_lookup_and_requested_refresh() => Handler.Requests.ShouldEqual(2);
}
