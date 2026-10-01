// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerIssuerMetadata;

public class when_an_automatic_refresh_retry_is_due : given.a_cached_issuer
{
    IReadOnlyCollection<SecurityKey>? _keys;

    async Task Establish()
    {
        Clock.Advance(TimeSpan.FromHours(13));
        Handler.Unavailable = true;
        await Metadata.GetSigningKeys(Issuer, CancellationToken.None, refresh: true);
        Clock.Advance(BearerIssuerMetadata.RefreshInterval + TimeSpan.FromSeconds(1));
        Handler.Delay = true;
    }

    async Task Because()
    {
        var lookup = Metadata.GetSigningKeys(Issuer, CancellationToken.None);
        await Handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        _keys = await lookup.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
    }

    [Fact] void should_answer_the_initiating_lookup_before_the_retry_finishes() => _keys!.Single().KeyId.ShouldEqual("known");
    [Fact] void should_start_the_retry_after_the_failure_backoff() => Handler.Requests.ShouldEqual(3);
    [Fact] void should_not_need_the_unavailable_issuer_to_finish() => Handler.Release.Task.IsCompleted.ShouldBeFalse();
}
