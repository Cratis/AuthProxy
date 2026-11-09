// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.Introspection;

namespace Cratis.AuthProxy.BearerRoutes.for_IntrospectionCache;

/// <summary>
/// An active answer is reused only briefly and only for the exact token it was given for. The cache never holds
/// a token, never grows past its cap, never keeps an answer past its expiry and never evicts a live answer to
/// make room.
/// </summary>
public class when_storing_answers : Specification
{
    const string Token = "header.payload.signature";
    const string Endpoint = "https://auth.example.test/connect/introspect";

    ManualTimeProvider _time;
    IntrospectionCache _cache;
    string _key;
    bool _storedFirst;
    bool _storedSecondWhenFull;
    bool _storedWithoutLifetime;
    bool _freshBeforeExpiry;
    bool _freshAtExpiry;
    bool _lookalikeHit;
    bool _otherEndpointHit;
    bool _otherClientHit;
    bool _fullCacheAfterSweep;
    bool _liveEntryStillThere;
    IReadOnlyCollection<string> _keys;

    void Establish()
    {
        _time = new ManualTimeProvider();
        _cache = new IntrospectionCache(_time);
        _key = IntrospectionCache.CreateKey(Endpoint, "authproxy", Token);
    }

    void Because()
    {
        _storedWithoutLifetime = _cache.Store(_key, TimeSpan.Zero, 10);
        _storedFirst = _cache.Store(_key, TimeSpan.FromSeconds(30), 10);

        _lookalikeHit = _cache.IsActive(IntrospectionCache.CreateKey(Endpoint, "authproxy", Token + " "))
            || _cache.IsActive(IntrospectionCache.CreateKey(Endpoint, "authproxy", Token[..^1] + "x"));
        _otherEndpointHit = _cache.IsActive(IntrospectionCache.CreateKey("https://other.example.test/connect/introspect", "authproxy", Token));
        _otherClientHit = _cache.IsActive(IntrospectionCache.CreateKey(Endpoint, "another-client", Token));
        _keys = _cache.Keys;

        _time.Advance(TimeSpan.FromSeconds(29));
        _freshBeforeExpiry = _cache.IsActive(_key);
        _time.Advance(TimeSpan.FromSeconds(1));
        _freshAtExpiry = _cache.IsActive(_key);

        // A cap of one: a live entry is never evicted for a newcomer, an expired one is swept for it.
        var small = new IntrospectionCache(_time);
        small.Store("live", TimeSpan.FromSeconds(30), 1);
        _storedSecondWhenFull = small.Store("newcomer", TimeSpan.FromSeconds(30), 1);
        _liveEntryStillThere = small.IsActive("live");

        var sweeping = new IntrospectionCache(_time);
        sweeping.Store("stale", TimeSpan.FromSeconds(1), 1);
        _time.Advance(TimeSpan.FromSeconds(2));
        _fullCacheAfterSweep = sweeping.Store("newcomer", TimeSpan.FromSeconds(30), 1);
    }

    [Fact] void should_store_an_active_answer() => _storedFirst.ShouldBeTrue();
    [Fact] void should_not_store_an_answer_without_a_lifetime() => _storedWithoutLifetime.ShouldBeFalse();
    [Fact] void should_reuse_the_answer_before_it_expires() => _freshBeforeExpiry.ShouldBeTrue();
    [Fact] void should_not_reuse_the_answer_once_it_expires() => _freshAtExpiry.ShouldBeFalse();
    [Fact] void should_not_serve_a_token_that_only_looks_like_the_stored_one() => _lookalikeHit.ShouldBeFalse();
    [Fact] void should_not_share_an_entry_between_endpoints() => _otherEndpointHit.ShouldBeFalse();
    [Fact] void should_not_share_an_entry_between_clients() => _otherClientHit.ShouldBeFalse();
    [Fact] void should_not_hold_the_token_in_a_key() => _keys.ShouldNotContain(_ => _.Contains(Token, StringComparison.Ordinal));
    [Fact] void should_key_by_a_sha256_hash() => _keys.ShouldContainOnly(_key);
    [Fact] void should_not_grow_past_the_cap() => _storedSecondWhenFull.ShouldBeFalse();
    [Fact] void should_not_evict_a_live_answer_to_make_room() => _liveEntryStillThere.ShouldBeTrue();
    [Fact] void should_sweep_expired_answers_to_make_room() => _fullCacheAfterSweep.ShouldBeTrue();
}
