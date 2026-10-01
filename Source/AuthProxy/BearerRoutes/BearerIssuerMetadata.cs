// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Reads and caches the signing keys bearer-token issuers publish.
/// </summary>
/// <param name="httpClientFactory">The factory for the client the metadata and JWKS are read with.</param>
/// <param name="logger">The logger.</param>
/// <param name="timeProvider">The clock used for retrieval deadlines.</param>
/// <remarks>
/// Each issuer keeps its last good keys. Requested refreshes finish before keys are returned, so a token naming
/// a newly rotated key can be retried in the same request. Retrievals are serialized per issuer and failed
/// retrievals back off, including before the first success. Ordinary lookups use previously trusted keys without
/// waiting for an in-progress retrieval, and start due automatic refreshes in the background. An outage does not discard previously trusted keys.
/// Metadata naming another issuer is never cached or trusted.
/// </remarks>
public sealed class BearerIssuerMetadata(
    IHttpClientFactory httpClientFactory,
    ILogger<BearerIssuerMetadata> logger,
    TimeProvider? timeProvider = null) : IBearerIssuerMetadata, IDisposable
{
    /// <summary>
    /// The shortest interval between two requested refreshes of one issuer's metadata, and the failure backoff.
    /// </summary>
    public static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(30);

    readonly ConcurrentDictionary<(string Issuer, string Address, bool RequireHttps), BearerIssuerMetadataCache> _caches = new();
    readonly CancellationTokenSource _shutdown = new();
    readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    /// <inheritdoc/>
    public async Task<IReadOnlyCollection<SecurityKey>?> GetSigningKeys(ResolvedBearerIssuer issuer, CancellationToken cancellationToken, bool refresh = false)
    {
        var cache = CacheFor(issuer);
        if (!refresh && cache.Configuration is { } available)
        {
            if (cache.Gate.Wait(0))
            {
                if (ShouldRetrieve(cache, refresh: false))
                {
                    // The retrieval owns the gate until it finishes. No request, including this one, waits for it.
                    cache.BackgroundRefresh = Task.Run(() => RefreshInBackground(issuer, cache));
                }
                else
                {
                    cache.Gate.Release();
                }
            }

            return [.. available.SigningKeys];
        }

        await cache.Gate.WaitAsync(cancellationToken);
        try
        {
            if (ShouldRetrieve(cache, refresh))
            {
                await Retrieve(issuer, cache, refresh, cancellationToken);
            }

            return cache.Configuration is { } cached ? [.. cached.SigningKeys] : null;
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
        foreach (var cache in _caches.Values)
        {
            cache.Dispose();
        }
        _shutdown.Dispose();
    }

    bool ShouldRetrieve(BearerIssuerMetadataCache cache, bool refresh)
    {
        var now = _clock.GetUtcNow();
        return now >= cache.RetryAfter &&
            (cache.Configuration is null || now >= cache.AutomaticRefreshAfter || (refresh && now >= cache.RequestedRefreshAfter));
    }

    async Task RefreshInBackground(ResolvedBearerIssuer issuer, BearerIssuerMetadataCache cache)
    {
        try
        {
            await Retrieve(issuer, cache, refresh: false, _shutdown.Token);
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
        {
            // Shutdown cancels and joins background retrievals before disposing their gates.
        }
        finally
        {
            cache.Gate.Release();
        }
    }

    async Task Retrieve(ResolvedBearerIssuer issuer, BearerIssuerMetadataCache cache, bool refresh, CancellationToken cancellationToken)
    {
        if (refresh)
        {
            cache.RequestedRefreshAfter = _clock.GetUtcNow() + RefreshInterval;
        }

        try
        {
            var configuration = await OpenIdConnectConfigurationRetriever.GetAsync(issuer.MetadataAddress, cache.Retriever, cancellationToken);
            if (string.Equals(configuration.Issuer, issuer.Issuer, StringComparison.Ordinal))
            {
                cache.Configuration = configuration;
                cache.AutomaticRefreshAfter = _clock.GetUtcNow() + ConfigurationManager<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval;
            }
            else
            {
                logger.IssuerMetadataNamesAnotherIssuer(issuer.Issuer, issuer.MetadataAddress);
                cache.RetryAfter = _clock.GetUtcNow() + RefreshInterval;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            cache.RetryAfter = _clock.GetUtcNow() + RefreshInterval;
            logger.IssuerMetadataUnavailable(exception, issuer.Issuer, issuer.MetadataAddress);
        }
    }

    BearerIssuerMetadataCache CacheFor(ResolvedBearerIssuer issuer) =>
        _caches.GetOrAdd(
            (issuer.Issuer, issuer.MetadataAddress, issuer.RequireHttps),
            static (key, factory) => new BearerIssuerMetadataCache(new HttpDocumentRetriever(factory.CreateClient(BearerRouteDefaults.MetadataHttpClientName))
            {
                RequireHttps = key.RequireHttps,
            }),
            httpClientFactory);
}
