// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenStore;

public class when_reading_a_legacy_encrypted_session : given.a_user_token_store
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task should_keep_the_legacy_retention_policy(bool sliding)
    {
        _config.Session.SlidingExpiration = sliding;
        var protection = new EphemeralDataProtectionProvider();
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(_config);
        var store = new UserTokenStore(_cache, protection, monitor, _time);
        var id = await store.Create(new("work", "refresh"), CancellationToken.None);
        var payload = Encoding.UTF8.GetBytes("{\"Scheme\":\"work\",\"RefreshToken\":\"legacy\",\"Audiences\":[],\"ExpiresAt\":null}");
        await _cache.SetAsync(_cache.Written.Keys.Single(), protection.CreateProtector("Cratis.AuthProxy.UserTokens.v1").Protect(payload), new DistributedCacheEntryOptions { SlidingExpiration = TimeSpan.FromHours(12) }, TestContext.Current.CancellationToken);
        (await store.Get(id, CancellationToken.None)).ShouldEqual(new UserTokenSession("work", "legacy"));
        await store.Update(id, new("work", "rotated"), CancellationToken.None);
        _time.Advance(TimeSpan.FromHours(11));
        (await store.Get(id, CancellationToken.None)).ShouldNotBeNull();
        _time.Advance(TimeSpan.FromHours(2));
        var later = await store.Get(id, CancellationToken.None);
        if (sliding) later.ShouldNotBeNull();
        else later.ShouldBeNull();
    }
}
