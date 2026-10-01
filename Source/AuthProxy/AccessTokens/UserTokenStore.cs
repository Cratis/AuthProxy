// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
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
        var options = SessionEntryOptions();
        await Write(SessionKey(sessionId), new StoredSession(session.Scheme, session.RefreshToken, [], options.AbsoluteExpiration), options, cancellationToken);
        return sessionId;
    }

    /// <inheritdoc/>
    public async Task<UserTokenSession?> Get(string sessionId, CancellationToken cancellationToken) =>
        await Read<StoredSession>(SessionKey(sessionId), cancellationToken) is { } stored
            ? new UserTokenSession(stored.Scheme, stored.RefreshToken)
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
                await Write(SessionKey(sessionId), stored with { Scheme = session.Scheme, RefreshToken = session.RefreshToken }, SessionEntryOptions(stored.ExpiresAt), cancellationToken);
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
                await cache.RemoveAsync(AccessTokenKey(sessionId, audience), cancellationToken);
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
            ? await Read<CachedUserAccessToken>(AccessTokenKey(sessionId, audience), cancellationToken)
            : null;

    /// <inheritdoc/>
    public async Task SetAccessToken(string sessionId, string audience, CachedUserAccessToken token, DateTimeOffset renewAt, CancellationToken cancellationToken)
    {
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
                await Write(SessionKey(sessionId), stored with { Audiences = [.. stored.Audiences, audience] }, SessionEntryOptions(stored.ExpiresAt), cancellationToken);
            }

            var expiresAt = stored.ExpiresAt is { } sessionExpiry && sessionExpiry < renewAt ? sessionExpiry : renewAt;
            await Write(
                AccessTokenKey(sessionId, audience),
                token,
                new DistributedCacheEntryOptions { AbsoluteExpiration = expiresAt },
                cancellationToken);
        }
        finally
        {
            mutationLock.Release();
        }
    }

    static string SessionKey(string sessionId) => $"{KeyPrefix}{Hash(sessionId)}";

    static string AccessTokenKey(string sessionId, string audience) => $"{KeyPrefix}{Hash(sessionId)}:{audience}";

    /// <summary>
    /// Derives the cache key from the identifier rather than using it, so a cache that can be listed does not hand
    /// out the value the cookie proves possession with.
    /// </summary>
    /// <param name="value">The identifier.</param>
    /// <returns>The derived key.</returns>
    static string Hash(string value) => WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    SemaphoreSlim MutationLock(string sessionId) => _mutationLocks[(uint)StringComparer.Ordinal.GetHashCode(sessionId) % (uint)_mutationLocks.Length];

    DistributedCacheEntryOptions SessionEntryOptions(DateTimeOffset? expiresAt = null)
    {
        if (expiresAt is not null)
        {
            return new DistributedCacheEntryOptions { AbsoluteExpiration = expiresAt };
        }

        var current = session.CurrentValue.Session;
        var lifetime = current.Lifetime > TimeSpan.Zero ? current.Lifetime : C.Session.DefaultLifetime;
        return current.SlidingExpiration
            ? new DistributedCacheEntryOptions { SlidingExpiration = lifetime }
            : new DistributedCacheEntryOptions { AbsoluteExpiration = timeProvider.GetUtcNow().Add(lifetime) };
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

    sealed record StoredSession(string Scheme, string RefreshToken, string[] Audiences, DateTimeOffset? ExpiresAt);
}
