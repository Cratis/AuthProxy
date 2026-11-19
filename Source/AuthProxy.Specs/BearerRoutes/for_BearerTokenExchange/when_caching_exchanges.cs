// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using System.Text.Json;
using Cratis.AuthProxy.BearerRoutes.TokenExchange;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerTokenExchange;

public class when_caching_exchanges
{
    [Fact]
    public void should_separate_every_trusted_dimension_without_retaining_the_subject()
    {
        var configuration = when_identity_answers.Configuration();
        var original = TokenExchangeCache.CreateKey(configuration, "issuer-a", "tenant-a", "raw-token");
        var keys = new HashSet<string>
        {
            original,
            TokenExchangeCache.CreateKey(configuration, "issuer-b", "tenant-a", "raw-token"),
            TokenExchangeCache.CreateKey(configuration, "issuer-a", "tenant-b", "raw-token"),
            TokenExchangeCache.CreateKey(configuration, "issuer-a", "TENANT-A", "raw-token"),
            TokenExchangeCache.CreateKey(configuration, "issuer-a", "tenant-a", "other-token"),
        };
        configuration.Resource = "urn:other";
        keys.Add(TokenExchangeCache.CreateKey(configuration, "issuer-a", "tenant-a", "raw-token"));
        configuration.Scopes = ["other"];
        keys.Add(TokenExchangeCache.CreateKey(configuration, "issuer-a", "tenant-a", "raw-token"));
        keys.Count.ShouldEqual(7);
        original.Length.ShouldEqual(64);
        original.Contains("raw-token", StringComparison.Ordinal).ShouldBeFalse();
    }

    [Fact]
    public async Task should_single_flight_concurrent_requests()
    {
        var clock = new Clock();
        var cache = new TokenExchangeCache(clock);
        var completion = new TaskCompletionSource<TokenExchangeResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        Task<TokenExchangeResult> Exchange()
        {
            Interlocked.Increment(ref calls);
            return completion.Task;
        }
        var requests = Enumerable.Range(0, 20).Select(_ => Get(cache, "key", 10, Exchange)).ToArray();
        completion.SetResult(Success(clock, 300, 300));
        await Task.WhenAll(requests);
        calls.ShouldEqual(1);
    }

    [Theory]
    [InlineData(20, 300, 21)]
    [InlineData(300, 20, 21)]
    public async Task should_expire_at_the_shorter_authoritative_deadline(int lifetime, int expiration, int elapsed)
    {
        var clock = new Clock();
        var cache = new TokenExchangeCache(clock);
        var calls = 0;
        Task<TokenExchangeResult> Exchange()
        {
            calls++;
            return Task.FromResult(Success(clock, lifetime, expiration));
        }
        await Get(cache, "key", 10, Exchange);
        await Get(cache, "key", 10, Exchange);
        calls.ShouldEqual(1);
        clock.Now += TimeSpan.FromSeconds(elapsed);
        await Get(cache, "key", 10, Exchange);
        calls.ShouldEqual(2);
    }

    [Theory]
    [InlineData(TokenExchangeVerdict.Refused)]
    [InlineData(TokenExchangeVerdict.Unavailable)]
    public async Task should_not_cache_failures(TokenExchangeVerdict verdict)
    {
        var cache = new TokenExchangeCache(new Clock());
        var calls = 0;
        Task<TokenExchangeResult> Exchange()
        {
            calls++;
            return Task.FromResult(new TokenExchangeResult(verdict));
        }
        await Get(cache, "key", 1, Exchange);
        await Get(cache, "key", 1, Exchange);
        calls.ShouldEqual(2);
    }

    [Fact]
    public async Task should_not_cache_a_success_without_a_readable_expiration()
    {
        var cache = new TokenExchangeCache(new Clock());
        var calls = 0;
        Task<TokenExchangeResult> Exchange()
        {
            calls++;
            return Task.FromResult(new TokenExchangeResult(TokenExchangeVerdict.Success, "a.b.c", 300));
        }
        await Get(cache, "key", 10, Exchange);
        await Get(cache, "key", 10, Exchange);
        calls.ShouldEqual(2);
    }

    [Fact]
    public async Task should_bound_storage_and_support_explicit_eviction()
    {
        var clock = new Clock();
        var cache = new TokenExchangeCache(clock);
        var calls = 0;
        Task<TokenExchangeResult> Exchange()
        {
            calls++;
            return Task.FromResult(Success(clock, 300, 300));
        }
        await Get(cache, "a", 1, Exchange);
        await Get(cache, "b", 1, Exchange);
        await Get(cache, "a", 1, Exchange);
        calls.ShouldEqual(3);
        cache.Evict("a");
        await Get(cache, "a", 1, Exchange);
        calls.ShouldEqual(4);
    }

    static Task<TokenExchangeResult> Get(TokenExchangeCache cache, string key, int maximum, Func<Task<TokenExchangeResult>> exchange) =>
        cache.GetOrExchange(key, maximum, exchange, TestContext.Current.CancellationToken);

    static TokenExchangeResult Success(Clock clock, int lifetime, int expiration)
    {
        var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { exp = clock.Now.AddSeconds(expiration).ToUnixTimeSeconds() }))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return new(TokenExchangeVerdict.Success, $"eyJhbGciOiJSUzI1NiJ9.{payload}.c2ln", lifetime);
    }

    sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.FromUnixTimeSeconds(2000000000);

        public override DateTimeOffset GetUtcNow() => Now;
    }
}
