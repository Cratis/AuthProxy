// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenStore;

public class when_a_provider_session_has_sliding_retention : given.a_user_token_store
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task should_cap_new_retention_at_the_global_policy(bool globalSliding)
    {
        _config.Session.SlidingExpiration = globalSliding;
        var id = await _store.Create(new("work", "refresh") { Lifetime = TimeSpan.FromHours(24), Sliding = true }, CancellationToken.None);
        var read = await _store.Get(id, CancellationToken.None);
        read!.Lifetime.ShouldEqual(TimeSpan.FromHours(12));
        read.Sliding.ShouldEqual(globalSliding);
        read.ExpiresAt.ShouldEqual(globalSliding ? null : _time.GetUtcNow().AddHours(12));
    }

    [Fact]
    public async Task should_clamp_a_rewritten_span_to_a_shorter_global_ceiling()
    {
        _config.Session.SlidingExpiration = true;
        var id = await _store.Create(new("work", "refresh") { Lifetime = TimeSpan.FromHours(2), Sliding = true }, CancellationToken.None);
        _config.Session.Lifetime = TimeSpan.FromMinutes(1);
        await _store.Update(id, new("work", "rotated"), CancellationToken.None);
        _time.Advance(TimeSpan.FromMinutes(2));
        (await _store.Get(id, CancellationToken.None)).ShouldBeNull();
    }

    [Fact]
    public async Task should_keep_the_provider_span_across_rotation_and_audience_writes()
    {
        _config.Session.SlidingExpiration = true;
        var span = TimeSpan.FromHours(2);
        var id = await _store.Create(new("work", "refresh") { Lifetime = span, Sliding = true }, CancellationToken.None);
        _time.Advance(TimeSpan.FromMinutes(90));
        var read = await _store.Get(id, CancellationToken.None);
        read!.Lifetime.ShouldEqual(span);
        read.Sliding.ShouldEqual(true);
        await _store.Update(id, new("work", "rotated"), CancellationToken.None);
        await _store.SetAccessToken(new(id, "reporting"), new("access", _time.GetUtcNow().AddHours(3), _time.GetUtcNow().AddHours(3)), _time.GetUtcNow().AddHours(3), CancellationToken.None);
        _time.Advance(TimeSpan.FromMinutes(90));
        (await _store.Get(id, CancellationToken.None))!.RefreshToken.ShouldEqual("rotated");
        _time.Advance(span);
        (await _store.Get(id, CancellationToken.None)).ShouldBeNull();
        (await _store.GetAccessToken(id, "reporting", CancellationToken.None)).ShouldBeNull();
    }
}
