// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerIssuerMetadata;

public class when_an_automatic_refresh_is_due : given.a_cached_issuer
{
    IReadOnlyCollection<SecurityKey>? _keys;
    IReadOnlyCollection<SecurityKey>? _concurrent;

    void Establish()
    {
        Clock.Advance(TimeSpan.FromHours(13));
        Handler.Delay = true;
    }

    async Task Because()
    {
        var lookup = Metadata.GetSigningKeys(Issuer, CancellationToken.None);
        await Handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        _keys = await lookup.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        _concurrent = await Metadata.GetSigningKeys(Issuer, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
    }

    [Fact] void should_answer_the_initiating_lookup_before_the_issuer_responds() => _keys!.Single().KeyId.ShouldEqual("known");
    [Fact] void should_answer_concurrent_lookups_before_the_issuer_responds() => _concurrent!.Single().KeyId.ShouldEqual("known");
    [Fact] void should_start_only_one_background_refresh() => Handler.Requests.ShouldEqual(2);
    [Fact] void should_not_need_the_issuer_to_finish() => Handler.Release.Task.IsCompleted.ShouldBeFalse();
}
