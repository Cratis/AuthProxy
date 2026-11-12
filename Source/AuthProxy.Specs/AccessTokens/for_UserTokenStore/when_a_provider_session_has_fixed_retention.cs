// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenStore;

public class when_a_provider_session_has_fixed_retention : given.a_user_token_store
{
    [Fact]
    public async Task should_cap_a_new_fixed_deadline_at_the_global_lifetime()
    {
        var id = await _store.Create(new("work", "refresh") { ExpiresAt = _time.GetUtcNow().AddDays(1), Lifetime = TimeSpan.FromHours(24), Sliding = false }, CancellationToken.None);
        (await _store.Get(id, CancellationToken.None))!.ExpiresAt.ShouldEqual(_time.GetUtcNow().AddHours(12));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task should_preserve_its_deadline_across_reads_rotation_and_audience_writes(bool globalSliding)
    {
        _config.Session.SlidingExpiration = globalSliding;
        var deadline = _time.GetUtcNow().AddHours(2);
        var session = new UserTokenSession("work", "refresh") { ExpiresAt = deadline, Lifetime = TimeSpan.FromHours(2), Sliding = false };
        var id = await _store.Create(session, CancellationToken.None);
        var audience = new UserTokenAudience(id, "reporting");
        _time.Advance(TimeSpan.FromMinutes(90));
        (await _store.Get(id, CancellationToken.None))!.ExpiresAt.ShouldEqual(deadline);
        await _store.Update(id, new("work", "rotated"), CancellationToken.None);
        await _store.SetAccessToken(audience, new("access", deadline.AddHours(1), deadline.AddHours(1)), deadline.AddHours(1), CancellationToken.None);
        await _store.SetRefreshRejected(id, "reporting", deadline.AddHours(1), CancellationToken.None);
        (await _store.Get(id, CancellationToken.None))!.RefreshToken.ShouldEqual("rotated");
        _time.Advance(TimeSpan.FromMinutes(30));
        (await _store.Get(id, CancellationToken.None)).ShouldBeNull();
        (await _store.GetAccessToken(id, "reporting", CancellationToken.None)).ShouldBeNull();
        (await _store.IsRefreshRejected(id, "reporting", CancellationToken.None)).ShouldBeFalse();
        foreach (var key in _cache.Written.Keys) (await _cache.GetAsync(key, TestContext.Current.CancellationToken)).ShouldBeNull();
        await _store.Update(id, new("work", "late-rotation"), CancellationToken.None);
        (await _store.Get(id, CancellationToken.None)).ShouldBeNull();
    }
}
