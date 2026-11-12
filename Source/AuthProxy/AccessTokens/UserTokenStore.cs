// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.AccessTokens;

/// <summary>
/// Represents an implementation of <see cref="IUserTokenStore"/> on <see cref="IDistributedCache"/>, with every value
/// encrypted by ASP.NET Core Data Protection.
/// </summary>
/// <remarks>
/// The default cache is in the process's memory, so tokens live and die with the AuthProxy instance that obtained
/// them. Every audience a session obtained a token for is recorded on the session, so removing the session removes
/// them all.
/// </remarks>
/// <param name="cache">The <see cref="IDistributedCache"/> holding the entries.</param>
/// <param name="dataProtection">The <see cref="IDataProtectionProvider"/> encrypting them.</param>
/// <param name="session">The session configuration, which bounds how long an entry is kept.</param>
/// <param name="timeProvider">The <see cref="TimeProvider"/>.</param>
public sealed class UserTokenStore(
    IDistributedCache cache,
    IDataProtectionProvider dataProtection,
    IOptionsMonitor<C.AuthProxy> session,
    TimeProvider timeProvider) : IUserTokenStore
{
    const string KeyPrefix = "Cratis.AuthProxy.UserTokens:";

    readonly SemaphoreSlim[] _mutationLocks = [.. Enumerable.Range(0, 64).Select(_ => new SemaphoreSlim(1, 1))];
    readonly IDataProtector _protector = dataProtection.CreateProtector("Cratis.AuthProxy.UserTokens.v1");

    /// <inheritdoc/>
    public async Task<string> Create(UserTokenSession session, CancellationToken cancellationToken)
    {
        var sessionId = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var stored = LimitRetention(new StoredSession(session.Scheme, session.RefreshToken, [], session.ExpiresAt, session.Lifetime, session.Sliding));
        var options = SessionEntryOptions(stored);
        await Write(SessionKey(sessionId), stored with { ExpiresAt = options.AbsoluteExpiration }, options, cancellationToken);
        return sessionId;
    }

    /// <inheritdoc/>
    public async Task<UserTokenSession?> Get(string sessionId, CancellationToken cancellationToken) =>
        await Read<StoredSession>(SessionKey(sessionId), cancellationToken) is { } stored
            ? new UserTokenSession(stored.Scheme, stored.RefreshToken) { Lifetime = stored.Lifetime, Sliding = stored.Sliding, ExpiresAt = stored.Lifetime is null ? null : stored.ExpiresAt }
            : null;

    /// <inheritdoc/>
    public async Task Update(string sessionId, UserTokenSession session, CancellationToken cancellationToken)
    {
        var mutationLock = MutationLock(sessionId);
        await mutationLock.WaitAsync(cancellationToken);
        try
        {
            if (await Read<StoredSession>(SessionKey(sessionId), cancellationToken) is { } stored)
            {
                await Write(SessionKey(sessionId), stored with { Scheme = session.Scheme, RefreshToken = session.RefreshToken }, SessionEntryOptions(stored), cancellationToken);
            }
        }
        finally
        {
            mutationLock.Release();
        }
    }

    /// <inheritdoc/>
    public async Task Remove(string sessionId, CancellationToken cancellationToken)
    {
        var mutationLock = MutationLock(sessionId);
        await mutationLock.WaitAsync(cancellationToken);
        try
        {
            var stored = await Read<StoredSession>(SessionKey(sessionId), cancellationToken);
            foreach (var audience in stored?.Audiences ?? [])
            {
                var audienceKey = new UserTokenAudience(sessionId, audience);
                await cache.RemoveAsync(AccessTokenKey(audienceKey), cancellationToken);
                await cache.RemoveAsync(RefreshRejectionKey(audienceKey), cancellationToken);
            }

            await cache.RemoveAsync(SessionKey(sessionId), cancellationToken);
        }
        finally
        {
            mutationLock.Release();
        }
    }

    /// <inheritdoc/>
    public async Task<CachedUserAccessToken?> GetAccessToken(string sessionId, string audience, CancellationToken cancellationToken) =>
        await Get(sessionId, cancellationToken) is not null
            ? await Read<CachedUserAccessToken>(AccessTokenKey(new(sessionId, audience)), cancellationToken)
            : null;

    /// <inheritdoc/>
    public Task SetAccessToken(UserTokenAudience audience, CachedUserAccessToken token, DateTimeOffset renewAt, CancellationToken cancellationToken) =>
        SetAudienceEntry(new AudienceEntry(audience.SessionId, audience.Audience, AccessTokenKey(audience), renewAt), token, cancellationToken);

    /// <inheritdoc/>
    public async Task<bool> IsRefreshRejected(string sessionId, string audience, CancellationToken cancellationToken) =>
        await Get(sessionId, cancellationToken) is not null
        && await Read<RefreshRejection>(RefreshRejectionKey(new(sessionId, audience)), cancellationToken) is { } rejection
        && rejection.RetryAt > timeProvider.GetUtcNow();

    /// <inheritdoc/>
    public Task SetRefreshRejected(string sessionId, string audience, DateTimeOffset retryAt, CancellationToken cancellationToken) =>
        SetAudienceEntry(new AudienceEntry(sessionId, audience, RefreshRejectionKey(new(sessionId, audience)), retryAt), new RefreshRejection(retryAt), cancellationToken);

    static string SessionKey(string sessionId) => $"{KeyPrefix}{Hash(sessionId)}";

    static string AccessTokenKey(UserTokenAudience audience) => $"{KeyPrefix}{Hash(audience.SessionId)}:{audience.Audience}";

    static string RefreshRejectionKey(UserTokenAudience audience) => $"{AccessTokenKey(audience)}:rejected";

    /// <summary>
    /// Derives the cache key from the identifier rather than using it, so a cache that can be listed does not hand
    /// out the value the cookie proves possession with.
    /// </summary>
    /// <param name="value">The identifier.</param>
    /// <returns>The derived key.</returns>
    static string Hash(string value) => WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    async Task SetAudienceEntry<T>(AudienceEntry entry, T value, CancellationToken cancellationToken)
    {
        var sessionId = entry.SessionId;
        var audience = entry.Audience;
        var mutationLock = MutationLock(sessionId);
        await mutationLock.WaitAsync(cancellationToken);
        try
        {
            var stored = await Read<StoredSession>(SessionKey(sessionId), cancellationToken);
            if (stored is null)
            {
                // The session ended while the token was being obtained; keep nothing for it.
                return;
            }

            if (!stored.Audiences.Contains(audience, StringComparer.Ordinal))
            {
                await Write(SessionKey(sessionId), stored with { Audiences = [.. stored.Audiences, audience] }, SessionEntryOptions(stored), cancellationToken);
            }

            var expiry = stored.ExpiresAt is { } sessionExpiry && sessionExpiry < entry.ExpiresAt ? sessionExpiry : entry.ExpiresAt;
            await Write(
                entry.Key,
                value,
                new DistributedCacheEntryOptions { AbsoluteExpiration = expiry },
                cancellationToken);
        }
        finally
        {
            mutationLock.Release();
        }
    }

    SemaphoreSlim MutationLock(string sessionId) => _mutationLocks[(uint)StringComparer.Ordinal.GetHashCode(sessionId) % (uint)_mutationLocks.Length];

    StoredSession LimitRetention(StoredSession value)
    {
        if (value.Lifetime is null && value.Sliding is null) return value;
        var options = SessionEntryOptions(value with { ExpiresAt = null });
        var expiry = options.AbsoluteExpiration;
        if (value.ExpiresAt is { } earlier && earlier < expiry) expiry = earlier;
        return value with
        {
            Lifetime = options.SlidingExpiration ?? (options.AbsoluteExpiration - timeProvider.GetUtcNow()),
            Sliding = options.SlidingExpiration is not null,
            ExpiresAt = expiry
        };
    }

    DistributedCacheEntryOptions SessionEntryOptions(StoredSession stored)
    {
        if (stored.ExpiresAt is not null)
        {
            return new DistributedCacheEntryOptions { AbsoluteExpiration = stored.ExpiresAt };
        }

        var policy = SessionLifetimePolicy.Resolve(session.CurrentValue.Session, new C.ProviderSession
        {
            Lifetime = stored.Lifetime > TimeSpan.Zero ? stored.Lifetime : null,
            SlidingExpiration = stored.Sliding
        });
        return policy.Sliding
            ? new DistributedCacheEntryOptions { SlidingExpiration = policy.Lifetime }
            : new DistributedCacheEntryOptions { AbsoluteExpiration = timeProvider.GetUtcNow().Add(policy.Lifetime) };
    }

    async Task Write<T>(string key, T value, DistributedCacheEntryOptions options, CancellationToken cancellationToken) =>
        await cache.SetAsync(key, _protector.Protect(JsonSerializer.SerializeToUtf8Bytes(value)), options, cancellationToken);

    async Task<T?> Read<T>(string key, CancellationToken cancellationToken)
        where T : class
    {
        var protectedValue = await cache.GetAsync(key, cancellationToken);
        if (protectedValue is null)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<T>(_protector.Unprotect(protectedValue));
        }
        catch (CryptographicException)
        {
            // Written under a key ring this instance does not have; treat it as absent.
            return null;
        }
    }

    sealed record AudienceEntry(string SessionId, string Audience, string Key, DateTimeOffset ExpiresAt);

    sealed record StoredSession(string Scheme, string RefreshToken, string[] Audiences, DateTimeOffset? ExpiresAt, TimeSpan? Lifetime = null, bool? Sliding = null);

    sealed record RefreshRejection(DateTimeOffset RetryAt);
}
