// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Net;
using Cratis.AuthProxy.BearerRoutes;
using Microsoft.IdentityModel.Tokens;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Retrieves bounded, same-origin invitation metadata and caches only successfully validated public keys.
/// </summary>
/// <param name="httpClientFactory">The factory for the no-redirect metadata client.</param>
/// <param name="logger">The logger.</param>
/// <param name="timeProvider">The clock for refresh, backoff and staleness.</param>
public sealed class InvitationTokenKeys(IHttpClientFactory httpClientFactory, ILogger<InvitationTokenKeys> logger, TimeProvider timeProvider) : IInvitationTokenKeys, IDisposable
{
    /// <summary>The named client used for invitation-token metadata and JWKS.</summary>
    public const string HttpClientName = "Cratis.AuthProxy.InvitationTokenKeys";

    /// <summary>The maximum number of entries accepted in a JWKS.</summary>
    public const int MaximumKeys = 16;

    /// <summary>The maximum size of either response, in bytes.</summary>
    public const int MaximumResponseSize = 64 * 1024;

    /// <summary>The only accepted invitation-token signature algorithm.</summary>
    public const string Algorithm = SecurityAlgorithms.RsaSha256;

    /// <summary>The deadline for fetching each complete response.</summary>
    public static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(10);

    /// <summary>The minimum automatic refresh interval.</summary>
    public static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromSeconds(60);

    /// <summary>The default and maximum automatic refresh interval.</summary>
    public static readonly TimeSpan MaximumRefreshInterval = TimeSpan.FromHours(12);

    /// <summary>The minimum requested-refresh interval and failed-fetch backoff.</summary>
    public static readonly TimeSpan RequestedRefreshInterval = TimeSpan.FromSeconds(30);

    /// <summary>The maximum lifetime of last-good keys during an outage.</summary>
    public static readonly TimeSpan MaximumStaleness = TimeSpan.FromHours(24);

    readonly ConcurrentDictionary<(string Url, string Issuer, string Audience), InvitationTokenKeysCache> _caches = new();
    readonly CancellationTokenSource _shutdown = new();

    /// <inheritdoc/>
    public async Task<IReadOnlyDictionary<string, SecurityKey>?> GetSigningKeys(C.Invite invite, CancellationToken cancellationToken, bool refresh = false)
    {
        var identity = (Url: invite.TokenMetadataUrl, invite.Issuer, invite.Audience);
        var cache = _caches.GetOrAdd(identity, static _ => new InvitationTokenKeysCache());
        if (!refresh && Usable(cache.Snapshot) is { } available)
        {
            if (cache.Gate.Wait(0))
            {
                if (ShouldRetrieve(cache, refresh: false))
                {
                    cache.BackgroundRefresh = Task.Run(() => RefreshInBackground(identity, cache));
                }
                else
                {
                    cache.Gate.Release();
                }
            }
            return available.Keys;
        }

        await cache.Gate.WaitAsync(cancellationToken);
        try
        {
            if (ShouldRetrieve(cache, refresh))
            {
                await Retrieve(identity, cache, refresh, cancellationToken);
            }
            var snapshot = Usable(cache.Snapshot);
            if (snapshot is null && cache.Snapshot is not null)
            {
                logger.InvitationKeysStale(identity.Url);
            }
            return snapshot?.Keys;
        }
        finally
        {
            cache.Gate.Release();
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _shutdown.Cancel();
        var caches = _caches.Values.ToArray();
        var background = Task.WhenAll(caches.Select(cache => cache.BackgroundRefresh ?? Task.CompletedTask));
        if (background.IsCompleted)
        {
            DisposeResources(caches);
        }
        else
        {
            _ = background.ContinueWith(completed => DisposeResources(caches), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
    }

    void DisposeResources(InvitationTokenKeysCache[] caches)
    {
        foreach (var cache in caches)
        {
            cache.Dispose();
        }
        _shutdown.Dispose();
    }

    InvitationTokenKeysCache.KeySnapshot? Usable(InvitationTokenKeysCache.KeySnapshot? snapshot) =>
        snapshot is not null && timeProvider.GetUtcNow() - snapshot.FetchedAt <= MaximumStaleness ? snapshot : null;

    bool ShouldRetrieve(InvitationTokenKeysCache cache, bool refresh)
    {
        var now = timeProvider.GetUtcNow();
        return now >= cache.RetryAfter && (Usable(cache.Snapshot) is null || now >= cache.RefreshAfter || (refresh && now >= cache.RequestedRefreshAfter));
    }

    async Task RefreshInBackground((string Url, string Issuer, string Audience) identity, InvitationTokenKeysCache cache)
    {
        try
        {
            await Retrieve(identity, cache, refresh: false, _shutdown.Token);
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
        {
            // Disposal joins this task before disposing the gate.
        }
        finally
        {
            cache.Gate.Release();
        }
    }

    async Task Retrieve((string Url, string Issuer, string Audience) identity, InvitationTokenKeysCache cache, bool refresh, CancellationToken cancellationToken)
    {
        if (refresh)
        {
            cache.RequestedRefreshAfter = timeProvider.GetUtcNow() + RequestedRefreshInterval;
        }
        try
        {
            var result = await FetchKeys(identity, cancellationToken);
            if (result is null)
            {
                cache.RetryAfter = timeProvider.GetUtcNow() + RequestedRefreshInterval;
                return;
            }
            cache.Snapshot = new(result.Value.Keys, timeProvider.GetUtcNow());
            cache.RefreshAfter = timeProvider.GetUtcNow() + result.Value.RefreshInterval;
            if (result.Value.Keys.Count == 0)
            {
                logger.InvitationKeySetEmpty(identity.Url);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested || _shutdown.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            cache.RetryAfter = timeProvider.GetUtcNow() + RequestedRefreshInterval;
            logger.InvitationMetadataUnavailable(exception, identity.Url);
        }
    }

    async Task<(IReadOnlyDictionary<string, SecurityKey> Keys, TimeSpan RefreshInterval)?> FetchKeys((string Url, string Issuer, string Audience) identity, CancellationToken cancellationToken)
    {
        if (!BearerRouteTable.TryParseAuthorityUri(identity.Url, out var metadataUrl, out _))
        {
            logger.InvitationMetadataRejected(identity.Url, "Invalid configured metadata URL.");
            return null;
        }
        var metadata = await Fetch(metadataUrl, cancellationToken);
        if (!InvitationTokenMetadataDocument.TryParse(metadata.Bytes, metadataUrl, identity.Issuer, identity.Audience, out var jwksUri, out var failure))
        {
            logger.InvitationMetadataRejected(identity.Url, failure);
            return null;
        }
        var jwks = await Fetch(jwksUri, cancellationToken);
        if (!InvitationTokenKeySet.TryParse(jwks.Bytes, out var keys, out failure))
        {
            logger.InvitationMetadataRejected(jwksUri.AbsoluteUri, failure);
            return null;
        }
        var age = metadata.MaxAge < jwks.MaxAge ? metadata.MaxAge : jwks.MaxAge;
        var interval = age < MinimumRefreshInterval ? MinimumRefreshInterval : age > MaximumRefreshInterval ? MaximumRefreshInterval : age;
        return (keys, interval);
    }

    async Task<(byte[] Bytes, TimeSpan MaxAge)> Fetch(Uri uri, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdown.Token);
        deadline.CancelAfter(FetchTimeout);
        var client = httpClientFactory.CreateClient(HttpClientName);
        using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentLength > MaximumResponseSize)
        {
            throw new HttpRequestException("Invitation metadata response is not HTTP 200 or exceeds the size limit.");
        }
        await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
        var buffer = new byte[MaximumResponseSize + 1];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(length), deadline.Token);
            if (read == 0)
            {
                break;
            }
            length += read;
        }
        if (length > MaximumResponseSize)
        {
            throw new HttpRequestException("Invitation metadata response exceeds the size limit.");
        }
        var cache = response.Headers.CacheControl;
        var age = cache is { NoCache: true } or { NoStore: true } ? MinimumRefreshInterval : cache?.MaxAge ?? MaximumRefreshInterval;
        return (buffer[..length], age);
    }
}
